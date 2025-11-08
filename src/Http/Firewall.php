<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class Firewall
{
    public function __construct(private Config $config)
    {
    }

    public function decide(ServerRequestInterface $serverRequest): FirewallResult
    {
        $pendingRateLimitHeaders = null;

        // 0) Track (passive)
        foreach ($this->config->getTrackRules() as $throttleRule) {
            $name = $throttleRule->name();
            if ($throttleRule->filter()->matches($serverRequest) === true) {
                $key = $throttleRule->keyExtractor()->extract($serverRequest);
                if ($key !== null) {
                    $counterKey = $this->trackKey($name, (string)$key);
                    $count = $this->increment($counterKey, $throttleRule->period());
                    $this->config->incrementDiagnosticsCounter('track_hit', $name);
                    $this->dispatch(new TrackHit(
                        rule: $name,
                        key: (string)$key,
                        period: $throttleRule->period(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                }
            }
        }

        // 1) Safelist
        foreach ($this->config->getSafelistRules() as $throttleRule) {
            $name = $throttleRule->name();
            if ($throttleRule->matcher()->matches($serverRequest) === true) {
                $this->dispatch(new SafelistMatched($name, $serverRequest));
                $this->config->incrementDiagnosticsCounter('safelisted', $name);
                return FirewallResult::safelisted($name, ['X-Phirewall-Safelist' => $name]);
            }
        }

        // 2) Blocklist
        foreach ($this->config->getBlocklistRules() as $throttleRule) {
            $name = $throttleRule->name();
            if ($throttleRule->matcher()->matches($serverRequest) === true) {
                $this->dispatch(new BlocklistMatched($name, $serverRequest));
                $this->config->incrementDiagnosticsCounter('blocklisted', $name);
                return FirewallResult::blocked($name, 'blocklist', [
                    'X-Phirewall' => 'blocklist',
                    'X-Phirewall-Matched' => $name,
                ]);
            }
        }

        $cache = $this->config->cache;

        // 3) Fail2Ban
        foreach ($this->config->getFail2BanRules() as $throttleRule) {
            $name = $throttleRule->name();
            $key = $throttleRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $banKey = $this->banKey($name, (string)$key);
            if ($cache->has($banKey)) {
                $this->config->incrementDiagnosticsCounter('fail2ban_blocked', $name);
                return FirewallResult::blocked($name, 'fail2ban', [
                    'X-Phirewall' => 'fail2ban',
                    'X-Phirewall-Matched' => $name,
                ]);
            }

            if ($throttleRule->filter()->matches($serverRequest) === true) {
                $failKey = $this->failKey($name, $key);
                $count = $this->increment($failKey, $throttleRule->period());
                $this->config->incrementDiagnosticsCounter('fail2ban_fail_hit', $name);
                if ($count >= $throttleRule->threshold()) {
                    $cache->set($banKey, 1, $throttleRule->banSeconds());
                    $this->config->incrementDiagnosticsCounter('fail2ban_banned', $name);
                    $this->dispatch(new Fail2BanBanned(
                        rule: $name,
                        key: $key,
                        threshold: $throttleRule->threshold(),
                        period: $throttleRule->period(),
                        banSeconds: $throttleRule->banSeconds(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                }
            }
        }

        // 4) Throttle
        foreach ($this->config->getThrottleRules() as $name => $throttleRule) {
            $name = $throttleRule->name();
            $key = $throttleRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $counterKey = $this->throttleKey($name, (string)$key);
            $count = $this->increment($counterKey, $throttleRule->period());
            $limit = $throttleRule->limit();
            $retryAfter = $this->ttlRemaining($counterKey);
            $remaining = max(0, $limit - $count);

            if ($count > $limit) {
                $this->dispatch(new ThrottleExceeded(
                    rule: $name,
                    key: (string)$key,
                    limit: $limit,
                    period: $throttleRule->period(),
                    count: $count,
                    retryAfter: $retryAfter,
                    serverRequest: $serverRequest,
                ));
                $this->config->incrementDiagnosticsCounter('throttle_exceeded', $name);
                $headers = [
                    'X-Phirewall' => 'throttle',
                    'X-Phirewall-Matched' => $name,
                    'Retry-After' => (string)max(1, $retryAfter),
                ];
                if ($this->config->rateLimitHeadersEnabled()) {
                    $headers += [
                        'X-RateLimit-Limit' => (string)$limit,
                        'X-RateLimit-Remaining' => '0',
                        'X-RateLimit-Reset' => (string)max(1, $retryAfter),
                    ];
                }

                return FirewallResult::throttled($name, $retryAfter, $headers);
            }

            if ($this->config->rateLimitHeadersEnabled() && $pendingRateLimitHeaders === null) {
                $pendingRateLimitHeaders = [
                    'X-RateLimit-Limit' => (string)$limit,
                    'X-RateLimit-Remaining' => (string)$remaining,
                    'X-RateLimit-Reset' => (string)max(1, $retryAfter),
                ];
            }
        }

        $this->config->incrementDiagnosticsCounter('passed');
        return FirewallResult::pass($pendingRateLimitHeaders ?? []);
    }

    private function increment(string $key, int $period): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->increment($key, $period);
        }

        $value = $cache->get($key, 0);
        if (!is_int($value)) {
            $value = is_scalar($value) ? (int)$value : 0;
        }

        ++$value;
        if ($value === 1) {
            $cache->set($key, $value, $period);
        } else {
            $cache->set($key, $value);
        }

        return $value;
    }

    private function ttlRemaining(string $key): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->ttlRemaining($key);
        }

        return 60;
    }

    private function throttleKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':throttle:' . $safeName . ':' . $safeKey;
    }

    private function failKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':fail2ban:fail:' . $safeName . ':' . $safeKey;
    }

    private function banKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':fail2ban:ban:' . $safeName . ':' . $safeKey;
    }

    private function trackKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':track:' . $safeName . ':' . $safeKey;
    }

    private function normalizeKeyComponent(string $value): string
    {
        $original = trim($value);
        if ($original === '') {
            return 'empty';
        }

        $sanitized = preg_replace('/[^A-Za-z0-9._:-]/', '_', $original);
        if ($sanitized === null) {
            $sanitized = 'invalid';
        }

        $sanitized = preg_replace('/_+/', '_', $sanitized) ?? $sanitized;
        $max = 120;
        if (strlen($sanitized) > $max) {
            $hash = substr(sha1($original), 0, 12);
            $sanitized = substr($sanitized, 0, $max - 13) . '-' . $hash;
        }

        return $sanitized;
    }

    private function dispatch(object $event): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if ($dispatcher instanceof \Psr\EventDispatcher\EventDispatcherInterface) {
            $dispatcher->dispatch($event);
        }
    }
}
