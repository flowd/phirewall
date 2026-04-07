<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

/**
 * Value object returned by FixedWindowCounter::increment().
 *
 * Holds the incremented request count and the number of seconds remaining
 * in the current fixed window.
 */
final readonly class FixedWindowResult
{
    public function __construct(
        public int $count,
        public int $retryAfter,
    ) {
    }
}
