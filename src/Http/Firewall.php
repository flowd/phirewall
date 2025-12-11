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
        foreach ($this->config->getTrackRules() as $trackRule) {
            $name = $trackRule->name();
            if ($trackRule->filter()->match($serverRequest)->isMatch() === true) {
                $key = $trackRule->keyExtractor()->extract($serverRequest);
                if ($key !== null) {
                    $counterKey = $this->trackKey($name, (string)$key);
                    $count = $this->increment($counterKey, $trackRule->period());
                    $this->config->incrementDiagnosticsCounter('track_hit', $name);
                    $this->dispatch(new TrackHit(
                        rule: $name,
                        key: (string)$key,
                        period: $trackRule->period(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                }
            }
        }

        // 1) Safelist
        foreach ($this->config->getSafelistRules() as $safelistRule) {
            $name = $safelistRule->name();
            if ($safelistRule->matcher()->match($serverRequest)->isMatch() === true) {
                $this->dispatch(new SafelistMatched($name, $serverRequest));
                $this->config->incrementDiagnosticsCounter('safelisted', $name);
                return FirewallResult::safelisted($name, ['X-Phirewall-Safelist' => $name]);
            }
        }

        // 2) Blocklist
        foreach ($this->config->getBlocklistRules() as $blocklistRule) {
            $name = $blocklistRule->name();
            $match = $blocklistRule->matcher()->match($serverRequest);
            if ($match->isMatch() === true) {
                $this->dispatch(new BlocklistMatched($name, $serverRequest));
                $this->config->incrementDiagnosticsCounter('blocklisted', $name);
                $headers = [
                    'X-Phirewall' => 'blocklist',
                    'X-Phirewall-Matched' => $name,
                ];
                if ($this->config->owaspDiagnosticsHeaderEnabled() && $match->source() === 'owasp') {
                    $meta = $match->metadata();
                    if (isset($meta['owasp_rule_id'])) {
                        $headers['X-Phirewall-Owasp-Rule'] = (string)$meta['owasp_rule_id'];
                    }
                }

                return FirewallResult::blocked($name, 'blocklist', $headers);
            }
        }

        $cache = $this->config->cache;

        // 3) Fail2Ban
        foreach ($this->config->getFail2BanRules() as $fail2BanRule) {
            $name = $fail2BanRule->name();
            $key = $fail2BanRule->keyExtractor()->extract($serverRequest);
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

            if ($fail2BanRule->filter()->match($serverRequest)->isMatch() === true) {
                $failKey = $this->failKey($name, $key);
                $count = $this->increment($failKey, $fail2BanRule->period());
                $this->config->incrementDiagnosticsCounter('fail2ban_fail_hit', $name);
                if ($count >= $fail2BanRule->threshold()) {
                    $cache->set($banKey, 1, $fail2BanRule->banSeconds());
                    $this->config->incrementDiagnosticsCounter('fail2ban_banned', $name);
                    $this->dispatch(new Fail2BanBanned(
                        rule: $name,
                        key: $key,
                        threshold: $fail2BanRule->threshold(),
                        period: $fail2BanRule->period(),
                        banSeconds: $fail2BanRule->banSeconds(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                }
            }
        }

        // 4) Throttle
        foreach ($this->config->getThrottleRules() as $throttleRule) {
            $name = $throttleRule->name();
            $key = $throttleRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $counterKey = $this->throttleKey($name, $key);
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

        $now = time();
        $entry = $cache->get($key);

        // Normalize legacy/plain values to structured entry
        if (is_array($entry) && array_key_exists('count', $entry) && array_key_exists('expires_at', $entry)) {
            $count = (int)($entry['count'] ?? 0);
            $expiresAt = (int)($entry['expires_at'] ?? 0);
        } else {
            // Legacy integer/scalar or cache miss → start (or restart) a window
            $count = is_int($entry) ? $entry : (is_scalar($entry) ? (int)$entry : 0);
            $expiresAt = $now + $period;
        }

        // If the window already expired, reset counter and expiry
        if ($expiresAt <= $now || $count < 0) {
            $count = 0;
            $expiresAt = $now + $period;
        }

        ++$count;

        $ttl = max(1, $expiresAt - $now);
        $cache->set($key, ['count' => $count, 'expires_at' => $expiresAt], $ttl);

        return $count;
    }

    private function ttlRemaining(string $key): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->ttlRemaining($key);
        }

        $entry = $cache->get($key);
        if (!is_array($entry) || !array_key_exists('expires_at', $entry)) {
            return 0;
        }

        $expiresAt = (int)($entry['expires_at'] ?? 0);
        $now = time();
        $remaining = $expiresAt - $now;

        return $remaining > 0 ? $remaining : 0;
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
