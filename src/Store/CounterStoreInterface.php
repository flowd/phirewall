<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

/**
 * Optional extension for PSR-16 caches used by Middleware for precise
 * fixed-window counters and TTL inspection without coupling to a concrete store.
 */
interface CounterStoreInterface
{
    /**
     * Increment a counter within a fixed time window and return the new value.
     * Implementations should align expiry to the end of the current window.
     */
    public function increment(string $key, int $period): int;

    /**
     * Return the number of whole seconds remaining before the key expires.
     */
    public function ttlRemaining(string $key): int;
}
