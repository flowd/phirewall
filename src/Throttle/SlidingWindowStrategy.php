<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

use Closure;
use Flowd\Phirewall\CacheKeyGenerator;
use Psr\SimpleCache\CacheInterface;

/**
 * Sliding window throttle strategy using weighted average of two fixed windows.
 *
 * Prevents the "double burst" problem at window boundaries by computing a
 * weighted estimate:
 *
 *   estimate = previousCount * (1 - weight) + currentCount
 *   where weight = elapsed / period
 *
 * NOTE: The get->increment->set sequence is not atomic. Under high concurrency
 * a small number of requests may slip through at the exact moment the threshold
 * is crossed. This is acceptable for rate limiting (not a security boundary).
 */
final readonly class SlidingWindowStrategy implements ThrottleStrategyInterface
{
    /** @var Closure(): float */
    private Closure $nowProvider;

    /**
     * @param Closure(): float $nowProvider Returns the current time as float seconds since Unix epoch.
     */
    public function __construct(
        private CacheInterface $cache,
        private CacheKeyGenerator $cacheKeyGenerator,
        callable $nowProvider,
    ) {
        $this->nowProvider = $nowProvider(...);
    }

    public function increment(string $ruleName, string $key, int $period): ThrottleResult
    {
        if ($period <= 0) {
            throw new \InvalidArgumentException('Throttle period must be a positive integer');
        }

        $now = ($this->nowProvider)();
        $currentWindowStart = (int) (floor($now / $period) * $period);
        $previousWindowStart = $currentWindowStart - $period;

        $currentKey = $this->cacheKeyGenerator->slidingWindowKey($ruleName, $key, $currentWindowStart);
        $previousKey = $this->cacheKeyGenerator->slidingWindowKey($ruleName, $key, $previousWindowStart);

        // Get previous window count (may be 0 if expired or never set)
        $previousCount = $this->cache->get($previousKey);
        $previousCount = is_int($previousCount) ? $previousCount : 0;

        // NOTE: The get->increment->set sequence below is not atomic (TOCTOU).
        // Under high concurrency a small number of requests may slip through.
        // This is acceptable for rate limiting (not a security boundary).
        $currentCount = $this->cache->get($currentKey);
        $currentCount = is_int($currentCount) ? $currentCount : 0;
        ++$currentCount;
        // TTL = 2 * period so the previous window is still readable from the next window
        $this->cache->set($currentKey, $currentCount, 2 * $period);

        // Calculate weighted estimate
        $elapsed = $now - $currentWindowStart;
        $weight = $elapsed / $period;
        $weight = max(0.0, min(1.0, $weight));

        $estimate = $previousCount * (1.0 - $weight) + $currentCount;

        // Retry-after: seconds until the current fixed window ends
        $retryAfter = max(1, $currentWindowStart + $period - (int) $now);

        return new ThrottleResult($estimate, $retryAfter);
    }
}
