<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Store\ClockInterface;

final class FakeClock implements ClockInterface
{
    private float $now;

    public function __construct(?float $startAt = null)
    {
        $this->now = $startAt ?? 1_700_000_000.0; // arbitrary fixed epoch for determinism
    }

    public function now(): float
    {
        return $this->now;
    }

    public function advance(float $seconds): void
    {
        $this->now += $seconds;
    }
}
