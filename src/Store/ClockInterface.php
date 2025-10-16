<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

interface ClockInterface
{
    /**
     * Return the current time as float seconds since the Unix epoch.
     * Typically sourced from microtime(true).
     */
    public function now(): float;
}
