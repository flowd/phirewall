<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

/**
 * Strategy for counting and rate-limiting requests within a time window.
 */
interface ThrottleStrategyInterface
{
    /**
     * Increment the throttle counter and return the current estimate.
     */
    public function increment(string $ruleName, string $key, int $period): ThrottleResult;
}
