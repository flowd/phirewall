<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use DateInterval;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\SimpleCache\CacheInterface;

/**
 * Minimal test double for the two RedisCache behaviours the ban-registry tests rely on:
 *  - WRITE: validates the value is JSON-encodable and throws on un-encodable input (e.g. a
 *    malformed-UTF-8 array key), as a JSON_THROW_ON_ERROR backend does; the value itself is then
 *    stored verbatim in the inner {@see InMemoryCache}.
 *  - READ: a stored string that decodes to a JSON document (array or object, both yielded as a
 *    PHP array by json_decode(..., true)) is returned as that array, mirroring how RedisCache
 *    hands back an array for a stored JSON document.
 *
 * It intentionally does not reproduce RedisCache's full value serialization (scalars are not JSON
 * round-tripped); that is out of scope for these tests.
 */
final readonly class JsonDecodingCache implements CacheInterface, CounterStoreInterface
{
    private InMemoryCache $inner;

    public function __construct()
    {
        $this->inner = new InMemoryCache();
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->inner->get($key, $default);
        if (is_string($value)) {
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        // Mirror backends that JSON-encode on write: an un-encodable value (e.g. a malformed-UTF-8
        // array key) throws here, as RedisCache/PdoCache would with JSON_THROW_ON_ERROR.
        json_encode($value, JSON_THROW_ON_ERROR);

        return $this->inner->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        return $this->inner->delete($key);
    }

    public function clear(): bool
    {
        return $this->inner->clear();
    }

    public function has(string $key): bool
    {
        return $this->inner->has($key);
    }

    /**
     * @param iterable<string> $keys
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        // Route through set() so multi-key writes get the same JSON-encodability validation.
        $ok = true;
        foreach ($values as $key => $value) {
            $ok = $this->set((string) $key, $value, $ttl) && $ok;
        }

        return $ok;
    }

    /**
     * @param iterable<string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        return $this->inner->deleteMultiple($keys);
    }

    public function increment(string $key, int $period): int
    {
        return $this->inner->increment($key, $period);
    }

    public function ttlRemaining(string $key): int
    {
        return $this->inner->ttlRemaining($key);
    }
}
