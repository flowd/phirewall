<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

use Flowd\Phirewall\CacheKeyGenerator;
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
    private FixedWindowCounter $counter;

    public function __construct(
        CacheInterface $cache,
        private CacheKeyGenerator $cacheKeyGenerator,
    ) {
        $this->counter = new FixedWindowCounter($cache);
    }

    public function increment(string $ruleName, string $key, int $period): ThrottleResult
    {
        $counterKey = $this->cacheKeyGenerator->throttleKey($ruleName, $key);
        $result = $this->counter->increment($counterKey, $period);

        return new ThrottleResult((float) $result->count, $result->retryAfter);
    }
}
