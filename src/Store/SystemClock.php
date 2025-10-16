<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

final class SystemClock implements ClockInterface
{
    public function now(): float
    {
        return microtime(true);
    }
}
