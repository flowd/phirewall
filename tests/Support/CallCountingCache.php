<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use DateInterval;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache decorator that counts the cache operations it forwards.
 *
 * Used to assert that the fail2ban / allow2ban evaluators collapse their per-rule
 * ban-key existence checks into a single getMultiple() round-trip instead of one
 * has()/get() per rule (finding #7). It also implements {@see CounterStoreInterface}
 * so the precise-counter and TTL code paths (the ones exercised against Redis/PDO
 * in production) are taken, not the generic PSR-16 fallback.
 */
final class CallCountingCache implements CacheInterface, CounterStoreInterface
{
    public int $hasCalls = 0;

    public int $getCalls = 0;

    public int $getMultipleCalls = 0;

    public int $ttlRemainingCalls = 0;

    public function __construct(private readonly CacheInterface&CounterStoreInterface $inner)
    {
    }

    public function resetCounts(): void
    {
        $this->hasCalls = 0;
        $this->getCalls = 0;
        $this->getMultipleCalls = 0;
        $this->ttlRemainingCalls = 0;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        ++$this->getCalls;
        return $this->inner->get($key, $default);
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

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        ++$this->getMultipleCalls;
        return $this->inner->getMultiple($keys, $default);
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        return $this->inner->setMultiple($values, $ttl);
    }

    public function deleteMultiple(iterable $keys): bool
    {
        return $this->inner->deleteMultiple($keys);
    }

    public function has(string $key): bool
    {
        ++$this->hasCalls;
        return $this->inner->has($key);
    }

    public function increment(string $key, int $period): int
    {
        return $this->inner->increment($key, $period);
    }

    public function ttlRemaining(string $key): int
    {
        ++$this->ttlRemainingCalls;
        return $this->inner->ttlRemaining($key);
    }
}
