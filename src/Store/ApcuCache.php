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
final readonly class ApcuCache implements CacheInterface, CounterStoreInterface
{
    use KeyValidationTrait;
    use BulkCacheOperationsTrait;

    private const EXP_SUFFIX = '::exp';

    public function __construct(private string $namespace = 'Phirewall:')
    {
        if (!function_exists('apcu_enabled') || !apcu_enabled()) {
            throw new \RuntimeException('APCu extension is not enabled.');
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->validateKey($key);
        $success = false;
        $value = apcu_fetch($this->prefixKey($key), $success);
        if (!$success) {
            return $default;
        }

        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->validateKey($key);
        $namespacedKey = $this->prefixKey($key);
        $ttl = $this->ttlToSeconds($ttl);
        if ($ttl !== null && $ttl < 0) {
            // Expired
            apcu_delete($namespacedKey);
            return true;
        }

        return $ttl === null ? apcu_store($namespacedKey, $value) : apcu_store($namespacedKey, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        $this->validateKey($key);
        $namespacedKey = $this->prefixKey($key);
        apcu_delete($namespacedKey);
        apcu_delete($namespacedKey . self::EXP_SUFFIX);
        return true;
    }

    public function clear(): bool
    {
        $iterator = new \APCUIterator('/^' . preg_quote($this->namespace, '/') . '/');
        apcu_delete($iterator);
        return true;
    }

    public function has(string $key): bool
    {
        $this->validateKey($key);
        return apcu_exists($this->prefixKey($key));
    }

    /**
     * Atomic-like increment with window-aligned expiry.
     * We rely on apcu_add (atomic) + apcu_inc (atomic) to avoid races.
     */
    public function increment(string $key, int $period): int
    {
        $this->validateKey($key);
        $namespacedKey = $this->prefixKey($key);
        $expKey = $namespacedKey . self::EXP_SUFFIX;
        $now = time();
        $windowStart = intdiv($now, $period) * $period;
        $windowEnd = $windowStart + $period; // epoch seconds
        $ttl = max(1, $windowEnd - $now);

        // Ensure key exists with correct TTL; apcu_add is atomic and will not overwrite.
        apcu_add($namespacedKey, 0, $ttl);
        // Keep a sidecar expiry timestamp for ttlRemaining
        apcu_add($expKey, $windowEnd, $ttl);

        $success = false;
        $newValue = apcu_inc($namespacedKey, 1, $success);
        if ($success === true) {
            return $newValue;
        }

        // Fallback: set to 1 explicitly with TTL (handles non-integer or unexpected state)
        apcu_store($namespacedKey, 1, $ttl);
        apcu_store($expKey, $windowEnd, $ttl);
        return 1;
    }

    public function ttlRemaining(string $key): int
    {
        $this->validateKey($key);
        $success = false;
        $expiry = apcu_fetch($this->prefixKey($key) . self::EXP_SUFFIX, $success);
        if (!$success || !is_int($expiry)) {
            return 0;
        }

        $remaining = $expiry - time();
        return max($remaining, 0);
    }

    private function prefixKey(string $key): string
    {
        return $this->namespace . $key;
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
