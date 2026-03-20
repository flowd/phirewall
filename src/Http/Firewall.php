<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\PerformanceMeasured;
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
        $start = microtime(true);
        $decisionPath = 'passed';
        $decisionRule = null;

        $pendingRateLimitHeaders = null;

        // 0) Track (passive)
        foreach ($this->config->getTrackRules() as $trackRule) {
            $name = $trackRule->name();
            if ($trackRule->filter()->match($serverRequest)->isMatch() === true) {
                $key = $trackRule->keyExtractor()->extract($serverRequest);
                if ($key !== null) {
                    $counterKey = $this->config->cacheKeyGenerator()->trackKey($name, (string)$key);
                    $count = $this->increment($counterKey, $trackRule->period());

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

                $decisionPath = 'safelisted';
                $decisionRule = $name;
                $result = FirewallResult::safelisted($name, ['X-Phirewall-Safelist' => $name]);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }
        }

        // 2) Blocklist
        foreach ($this->config->getBlocklistRules() as $blocklistRule) {
            $name = $blocklistRule->name();
            $match = $blocklistRule->matcher()->match($serverRequest);
            if ($match->isMatch() === true) {
                $this->dispatch(new BlocklistMatched($name, $serverRequest));

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

                $decisionPath = 'blocklisted';
                $decisionRule = $name;
                $result = FirewallResult::blocked($name, 'blocklist', $headers);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }
        }

        $cache = $this->config->cache;

        // NOTE: The check → increment → threshold-check sequence is not atomic.
        // Under high concurrency, a small number of requests may slip through
        // at the exact moment the threshold is crossed. This is acceptable for
        // rate-limiting (not a security boundary) and matches fail2ban's pattern.

        // 3) Fail2Ban
        foreach ($this->config->getFail2BanRules() as $fail2BanRule) {
            $name = $fail2BanRule->name();
            $key = $fail2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $banKey = $this->config->cacheKeyGenerator()->fail2BanBanKey($name, (string)$key);
            if ($cache->has($banKey)) {

                $decisionPath = 'fail2ban_blocked';
                $decisionRule = $name;
                $result = FirewallResult::blocked($name, 'fail2ban', [
                    'X-Phirewall' => 'fail2ban',
                    'X-Phirewall-Matched' => $name,
                ]);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }

            if ($fail2BanRule->filter()->match($serverRequest)->isMatch() === true) {
                $failKey = $this->config->cacheKeyGenerator()->fail2BanFailKey($name, $key);
                $count = $this->increment($failKey, $fail2BanRule->period());

                if ($count >= $fail2BanRule->threshold()) {
                    $this->config->banManager()->ban($name, $key, $fail2BanRule->banSeconds(), BanType::Fail2Ban);

                    $this->dispatch(new Fail2BanBanned(
                        rule: $name,
                        key: $key,
                        threshold: $fail2BanRule->threshold(),
                        period: $fail2BanRule->period(),
                        banSeconds: $fail2BanRule->banSeconds(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                    $decisionPath = 'fail2ban_banned';
                    $decisionRule = $name;
                    $result = FirewallResult::blocked($name, 'fail2ban', [
                        'X-Phirewall' => 'fail2ban',
                        'X-Phirewall-Matched' => $name,
                    ]);
                    $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                    return $result;
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

            $counterKey = $this->config->cacheKeyGenerator()->throttleKey($name, $key);
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

                $decisionPath = 'throttled';
                $decisionRule = $name;
                $result = FirewallResult::throttled($name, $retryAfter, $headers);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }

            if ($this->config->rateLimitHeadersEnabled() && $pendingRateLimitHeaders === null) {
                $pendingRateLimitHeaders = [
                    'X-RateLimit-Limit' => (string)$limit,
                    'X-RateLimit-Remaining' => (string)$remaining,
                    'X-RateLimit-Reset' => (string)max(1, $retryAfter),
                ];
            }
        }

        // 5) Allow2Ban
        // Process all rules so every counter is incremented, then return the first block.
        $allow2BanResult = null;
        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $name = $allow2BanRule->name();
            $key = $allow2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $a2bBanKey = $this->config->cacheKeyGenerator()->allow2BanBanKey($name, $key);
            if ($cache->has($a2bBanKey)) {
                $banRetryAfter = $this->ttlRemaining($a2bBanKey);
                if ($banRetryAfter < 1) {
                    $banRetryAfter = $allow2BanRule->banSeconds();
                }

                $allow2BanResult ??= ['path' => 'allow2ban_blocked', 'rule' => $name, 'result' => FirewallResult::blocked($name, 'allow2ban', [
                    'X-Phirewall' => 'allow2ban',
                    'X-Phirewall-Matched' => $name,
                    'Retry-After' => (string) $banRetryAfter,
                ])];
                continue;
            }

            $a2bHitKey = $this->config->cacheKeyGenerator()->allow2BanHitKey($name, $key);
            $count = $this->increment($a2bHitKey, $allow2BanRule->period());

            if ($count >= $allow2BanRule->threshold()) {
                $this->config->banManager()->ban($name, $key, $allow2BanRule->banSeconds(), BanType::Allow2Ban);
                $cache->delete($a2bHitKey);

                $this->dispatch(new Allow2BanBanned(
                    rule: $name,
                    key: $key,
                    threshold: $allow2BanRule->threshold(),
                    period: $allow2BanRule->period(),
                    banSeconds: $allow2BanRule->banSeconds(),
                    count: $count,
                    serverRequest: $serverRequest,
                ));
                $newBanRetryAfter = $this->ttlRemaining($a2bBanKey);
                if ($newBanRetryAfter < 1) {
                    $newBanRetryAfter = $allow2BanRule->banSeconds();
                }

                $allow2BanResult ??= ['path' => 'allow2ban_banned', 'rule' => $name, 'result' => FirewallResult::blocked($name, 'allow2ban', [
                    'X-Phirewall' => 'allow2ban',
                    'X-Phirewall-Matched' => $name,
                    'Retry-After' => (string) $newBanRetryAfter,
                ])];
            }
        }

        if ($allow2BanResult !== null) {
            $decisionPath = $allow2BanResult['path'];
            $decisionRule = $allow2BanResult['rule'];
            $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
            return $allow2BanResult['result'];
        }


        $result = FirewallResult::pass($pendingRateLimitHeaders ?? []);
        $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
        return $result;
    }

    private function dispatchPerformanceMeasured(float $start, string $decisionPath, ?string $ruleName): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if (!$dispatcher instanceof \Psr\EventDispatcher\EventDispatcherInterface) {
            return;
        }

        $durationMicros = (int) round((microtime(true) - $start) * 1_000_000);
        if ($durationMicros < 0) {
            $durationMicros = 0;
        }

        $dispatcher->dispatch(new PerformanceMeasured($decisionPath, $durationMicros, $ruleName));
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
        if (
            is_array($entry)
            && is_scalar($entry['count'] ?? null)
            && is_scalar($entry['expires_at'] ?? null)
        ) {
            $count = (int)($entry['count'] ?? 0);
            $expiresAt = (int)($entry['expires_at'] ?? 0);
        } else {
            // Legacy integer/scalar or cache miss → start (or restart) a window
            $count = is_scalar($entry) ? (int)$entry : 0;
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
        if (!is_array($entry) || !is_scalar($entry['count'] ?? null)) {
            return 0;
        }

        $expiresAt = (int)($entry['expires_at'] ?? 0);
        $now = time();
        $remaining = $expiresAt - $now;

        return max($remaining, 0);
    }

    private function dispatch(object $event): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if ($dispatcher instanceof \Psr\EventDispatcher\EventDispatcherInterface) {
            $dispatcher->dispatch($event);
        }
    }
}
