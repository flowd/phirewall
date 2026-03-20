<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

/**
 * Represents the result of a throttle strategy increment operation.
 *
 * The count may be a float when using the sliding window strategy
 * (weighted average of two fixed windows).
 */
final readonly class ThrottleResult
{
    public function __construct(
        public float $count,
        public int $retryAfter,
    ) {
    }
}
