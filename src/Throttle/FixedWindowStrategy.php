<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

use Flowd\Phirewall\CacheKeyGenerator;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Fixed-window throttle strategy.
 *
 * Divides time into fixed periods and counts requests within each window.
 * Simple and efficient, but susceptible to the "double burst" problem at
 * window boundaries.
 */
final readonly class FixedWindowStrategy implements ThrottleStrategyInterface
{
    public function __construct(
        private CacheInterface $cache,
        private CacheKeyGenerator $cacheKeyGenerator,
    ) {
    }

    public function increment(string $ruleName, string $key, int $period): ThrottleResult
    {
        $counterKey = $this->cacheKeyGenerator->throttleKey($ruleName, $key);

        if ($this->cache instanceof CounterStoreInterface) {
            $count = $this->cache->increment($counterKey, $period);
            $retryAfter = $this->cache->ttlRemaining($counterKey);

            return new ThrottleResult((float) $count, $retryAfter);
        }

        $now = time();
        $entry = $this->cache->get($counterKey);

        if (
            is_array($entry)
            && is_scalar($entry['count'] ?? null)
            && is_scalar($entry['expires_at'] ?? null)
        ) {
            $count = (int) ($entry['count'] ?? 0);
            $expiresAt = (int) ($entry['expires_at'] ?? 0);
        } else {
            $count = is_scalar($entry) ? (int) $entry : 0;
            $expiresAt = $now + $period;
        }

        if ($expiresAt <= $now || $count < 0) {
            $count = 0;
            $expiresAt = $now + $period;
        }

        ++$count;

        $ttl = max(1, $expiresAt - $now);
        $this->cache->set($counterKey, ['count' => $count, 'expires_at' => $expiresAt], $ttl);

        $retryAfter = max(0, $expiresAt - $now);

        return new ThrottleResult((float) $count, $retryAfter);
    }
}
