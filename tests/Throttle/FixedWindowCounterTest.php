<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Throttle;

use DateInterval;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Flowd\Phirewall\Throttle\FixedWindowCounter;
use Flowd\Phirewall\Throttle\FixedWindowResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

#[CoversClass(\Flowd\Phirewall\Throttle\FixedWindowCounter::class)]
final class FixedWindowCounterTest extends TestCase
{
    /**
     * @return array{ArrayCache, FixedWindowCounter}
     */
    private function createCounter(): array
    {
        $cache = new ArrayCache();

        return [$cache, new FixedWindowCounter($cache)];
    }

    public function testFirstIncrementReturnsOne(): void
    {
        [, $counter] = $this->createCounter();

        $result = $counter->increment('test-key', 60);

        $this->assertInstanceOf(FixedWindowResult::class, $result);
        $this->assertSame(1, $result->count);
        $this->assertGreaterThan(0, $result->retryAfter);
        $this->assertLessThanOrEqual(60, $result->retryAfter);
    }

    public function testConsecutiveIncrementsAccumulate(): void
    {
        [, $counter] = $this->createCounter();

        $result1 = $counter->increment('key', 60);
        $result2 = $counter->increment('key', 60);
        $result3 = $counter->increment('key', 60);

        $this->assertSame(1, $result1->count);
        $this->assertSame(2, $result2->count);
        $this->assertSame(3, $result3->count);
    }

    public function testDifferentKeysAreIndependent(): void
    {
        [, $counter] = $this->createCounter();

        $resultA = $counter->increment('key-a', 60);
        $resultB = $counter->increment('key-b', 60);

        $this->assertSame(1, $resultA->count);
        $this->assertSame(1, $resultB->count);
    }

    public function testExpiredWindowResetsCounter(): void
    {
        [$cache, $counter] = $this->createCounter();

        $cache->set('expired-key', [
            'count' => 5,
            'expires_at' => time() - 10,
        ]);

        $result = $counter->increment('expired-key', 60);

        $this->assertSame(1, $result->count);
    }

    public function testNegativeCountResetsWindow(): void
    {
        [$cache, $counter] = $this->createCounter();

        $cache->set('negative-key', [
            'count' => -3,
            'expires_at' => time() + 30,
        ]);

        $result = $counter->increment('negative-key', 60);

        $this->assertSame(1, $result->count);
    }

    public function testLegacyScalarEntryIsMigrated(): void
    {
        [$cache, $counter] = $this->createCounter();

        // Pre-seed with a legacy plain integer value (old cache format)
        $cache->set('legacy-key', 7);

        $result = $counter->increment('legacy-key', 60);

        // Legacy value 7 is treated as current count, so incremented to 8
        $this->assertSame(8, $result->count);
    }

    public function testLegacyStringEntryIsMigrated(): void
    {
        [$cache, $counter] = $this->createCounter();

        $cache->set('legacy-str-key', '3');

        $result = $counter->increment('legacy-str-key', 60);

        $this->assertSame(4, $result->count);
    }

    public function testCacheMissStartsFreshWindow(): void
    {
        [, $counter] = $this->createCounter();

        $result = $counter->increment('missing-key', 120);

        $this->assertSame(1, $result->count);
        $this->assertGreaterThan(0, $result->retryAfter);
        $this->assertLessThanOrEqual(120, $result->retryAfter);
    }

    public function testRetryAfterIsZeroOrPositive(): void
    {
        [, $counter] = $this->createCounter();

        $result = $counter->increment('key', 30);

        $this->assertGreaterThanOrEqual(0, $result->retryAfter);
    }

    public function testStructuredEntryWithinWindowPreservesExpiry(): void
    {
        [$cache, $counter] = $this->createCounter();

        $futureExpiry = time() + 45;
        $cache->set('struct-key', [
            'count' => 2,
            'expires_at' => $futureExpiry,
        ]);

        $result = $counter->increment('struct-key', 60);

        $this->assertSame(3, $result->count);

        // The stored entry should preserve the original expires_at
        $storedEntry = $cache->get('struct-key');
        $this->assertIsArray($storedEntry);
        $this->assertSame($futureExpiry, $storedEntry['expires_at']);
    }

    public function testNonScalarEntryIsTreatedAsCacheMiss(): void
    {
        [$cache, $counter] = $this->createCounter();

        $cache->set('weird-key', ['something' => 'else']);

        $result = $counter->increment('weird-key', 60);

        $this->assertSame(1, $result->count);
    }

    public function testTtlStoredInCacheIsPositive(): void
    {
        [$cache, $counter] = $this->createCounter();

        $counter->increment('ttl-key', 60);

        $lastTtl = $cache->getLastTtl();
        $this->assertNotNull($lastTtl);
        $this->assertGreaterThanOrEqual(1, $lastTtl);
    }

    public function testCounterStoreFastPathDelegatesToIncrement(): void
    {
        $cache = new CounterStoreArrayCache();
        $counter = new FixedWindowCounter($cache);

        $result = $counter->increment('fast-key', 60);

        $this->assertInstanceOf(FixedWindowResult::class, $result);
        $this->assertSame(1, $result->count);
        $this->assertSame(60, $result->retryAfter);
    }

    public function testCounterStoreFastPathAccumulates(): void
    {
        $cache = new CounterStoreArrayCache();
        $counter = new FixedWindowCounter($cache);

        $counter->increment('acc-key', 30);
        $counter->increment('acc-key', 30);

        $result = $counter->increment('acc-key', 30);

        $this->assertSame(3, $result->count);
        $this->assertSame(30, $result->retryAfter);
    }

    public function testInvalidPeriodThrowsException(): void
    {
        [, $counter] = $this->createCounter();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Period must be >= 1 second, got 0.');
        $counter->increment('key', 0);
    }

    public function testNegativePeriodThrowsException(): void
    {
        [, $counter] = $this->createCounter();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Period must be >= 1 second, got -5.');
        $counter->increment('key', -5);
    }

    public function testCounterStoreInvalidPeriodThrowsException(): void
    {
        $cache = new CounterStoreArrayCache();
        $counter = new FixedWindowCounter($cache);

        $this->expectException(\InvalidArgumentException::class);
        $counter->increment('key', 0);
    }
}

/**
 * Minimal PSR-16 array cache for testing FixedWindowCounter.
 *
 * Does NOT implement CounterStoreInterface, so the counter's own logic
 * is exercised instead of being bypassed by a fast-path.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $data = [];

    private int|null $lastTtl = null;

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->lastTtl = $ttl instanceof DateInterval ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time() : $ttl;

        $this->data[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->data = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function getLastTtl(): int|null
    {
        return $this->lastTtl;
    }
}

/**
 * Minimal PSR-16 + CounterStoreInterface cache for testing the fast-path.
 */
final class CounterStoreArrayCache implements CacheInterface, CounterStoreInterface
{
    /** @var array<string, mixed> */
    private array $data = [];

    /** @var array<string, int> */
    private array $counters = [];

    /** @var array<string, int> */
    private array $periods = [];

    public function increment(string $key, int $period): int
    {
        $this->counters[$key] = ($this->counters[$key] ?? 0) + 1;
        $this->periods[$key] = $period;

        return $this->counters[$key];
    }

    public function ttlRemaining(string $key): int
    {
        return $this->periods[$key] ?? 0;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->data[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->data = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }
}
