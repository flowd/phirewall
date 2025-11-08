<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/**
 * APCu-backed PSR-16 cache with CounterStoreInterface helpers.
 *
 * Notes:
 * - Requires ext-apcu and apcu.enable_cli=1 for CLI testing.
 * - For counters, we use fixed-window expiry aligned to period end and
 *   maintain a companion expiry key to compute ttlRemaining accurately.
 */
final class ApcuCache implements CacheInterface, CounterStoreInterface
{
    private const EXP_SUFFIX = '::exp';

    public function get(string $key, mixed $default = null): mixed
    {
        $success = false;
        $value = apcu_fetch($key, $success);
        if (!$success) {
            return $default;
        }
        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $ttl = $this->ttlToSeconds($ttl);
        if ($ttl !== null && $ttl < 0) {
            // Expired
            apcu_delete($key);
            return true;
        }
        return $ttl === null ? apcu_store($key, $value) : apcu_store($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        apcu_delete($key);
        apcu_delete($key . self::EXP_SUFFIX);
        return true;
    }

    public function clear(): bool
    {
        apcu_clear_cache();
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get((string)$key, $default);
        }
        return $result;
    }

    /**
     * @param iterable<string|int, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string)$key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string)$key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return apcu_exists($key);
    }

    /**
     * Atomic-like increment with window-aligned expiry.
     * We rely on apcu_add (atomic) + apcu_inc (atomic) to avoid races.
     */
    public function increment(string $key, int $period): int
    {
        $now = time();
        $windowStart = intdiv($now, $period) * $period;
        $windowEnd = $windowStart + $period; // epoch seconds
        $ttl = max(1, $windowEnd - $now);

        // Ensure key exists with correct TTL; apcu_add is atomic and will not overwrite.
        apcu_add($key, 0, $ttl);
        // Keep a sidecar expiry timestamp for ttlRemaining
        apcu_add($key . self::EXP_SUFFIX, $windowEnd, $ttl);

        $success = false;
        $newValue = apcu_inc($key, 1, $success);
        if ($success === true && is_int($newValue)) {
            return $newValue;
        }

        // Fallback: set to 1 explicitly with TTL (handles non-integer or unexpected state)
        apcu_store($key, 1, $ttl);
        apcu_store($key . self::EXP_SUFFIX, $windowEnd, $ttl);
        return 1;
    }

    public function ttlRemaining(string $key): int
    {
        $success = false;
        $expiry = apcu_fetch($key . self::EXP_SUFFIX, $success);
        if (!$success || !is_int($expiry)) {
            return 0;
        }
        $remaining = $expiry - time();
        return $remaining > 0 ? $remaining : 0;
    }

    private function ttlToSeconds(null|int|DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }
        if ($ttl instanceof DateInterval) {
            $now = new \DateTimeImmutable();
            $seconds = $now->add($ttl)->getTimestamp() - $now->getTimestamp();
            return max(0, $seconds);
        }
        return $ttl;
    }
}
