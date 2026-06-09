<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use DateInterval;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\SimpleCache\CacheInterface;

/**
 * Cache that models RedisCache's documented read behaviour: a stored string that parses as a
 * JSON array is returned as the decoded array. Delegates to an inner {@see InMemoryCache} (which
 * is final, hence composition) and only re-types the value on read. Used to exercise consumers
 * such as the ban registry against a backend that does not round-trip a JSON-encoded string.
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
        return $this->inner->setMultiple($values, $ttl);
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
