<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Throttle;

use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Encapsulates the fixed-window counter logic shared across the firewall.
 *
 * Used by Firewall (fail2ban, allow2ban, track counters) and FixedWindowStrategy
 * (throttle counters). When the cache implements CounterStoreInterface, the
 * native atomic increment is used as a fast path.
 *
 * NOTE: The get→increment→set fallback is not atomic (TOCTOU). Under high
 * concurrency a small number of requests may slip through at the exact moment
 * the threshold is crossed. This is acceptable for rate limiting (not a
 * security boundary).
 */
final readonly class FixedWindowCounter
{
    public function __construct(private CacheInterface $cache)
    {
    }

    /**
     * Increment a fixed-window counter and return the new count and time remaining.
     *
     * @param string $key The fully-qualified cache key for this counter.
     * @param int $period The window length in seconds.
     */
    public function increment(string $key, int $period): FixedWindowResult
    {
        if ($this->cache instanceof CounterStoreInterface) {
            $count = $this->cache->increment($key, $period);
            $retryAfter = $this->cache->ttlRemaining($key);

            return new FixedWindowResult($count, $retryAfter);
        }

        $now = time();
        $entry = $this->cache->get($key);

        // Normalize legacy/plain values to structured entry
        if (
            is_array($entry)
            && is_scalar($entry['count'] ?? null)
            && is_scalar($entry['expires_at'] ?? null)
        ) {
            $count = (int) ($entry['count'] ?? 0);
            $expiresAt = (int) ($entry['expires_at'] ?? 0);
        } else {
            // Legacy integer/scalar or cache miss → start (or restart) a window
            $count = is_scalar($entry) ? (int) $entry : 0;
            $expiresAt = $now + $period;
        }

        // If the window already expired, reset counter and expiry
        if ($expiresAt <= $now || $count < 0) {
            $count = 0;
            $expiresAt = $now + $period;
        }

        ++$count;

        $ttl = max(1, $expiresAt - $now);
        $this->cache->set($key, ['count' => $count, 'expires_at' => $expiresAt], $ttl);

        $retryAfter = max(0, $expiresAt - $now);

        return new FixedWindowResult($count, $retryAfter);
    }
}
