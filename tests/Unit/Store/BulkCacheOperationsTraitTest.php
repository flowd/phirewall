<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\BulkCacheOperationsTrait;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Store\PdoCache;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

/**
 * The shared trivial bulk operations live in {@see BulkCacheOperationsTrait};
 * this exercises the inherited get/set/deleteMultiple loops through the backends
 * that use it and confirms backends with batched overrides still delegate.
 */
#[CoversClass(BulkCacheOperationsTrait::class)]
final class BulkCacheOperationsTraitTest extends TestCase
{
    /**
     * Backends whose bulk methods come (at least partly) from the trait.
     *
     * @return iterable<string, array{0: callable(): CacheInterface}>
     */
    public static function traitUsingBackends(): iterable
    {
        yield 'InMemoryCache' => [static fn(): CacheInterface => new InMemoryCache()];
        yield 'PdoCache (sqlite)' => [static fn(): CacheInterface => new PdoCache(new PDO('sqlite::memory:'))];
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('traitUsingBackends')]
    public function testSetMultipleThenGetMultipleRoundTrips(callable $factory): void
    {
        $cache = $factory();

        $this->assertTrue($cache->setMultiple(['alpha' => 1, 'beta' => 2, 'gamma' => 3]));

        $this->assertSame(
            ['alpha' => 1, 'beta' => 2, 'gamma' => 3],
            $this->toArray($cache->getMultiple(['alpha', 'beta', 'gamma'])),
        );
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('traitUsingBackends')]
    public function testGetMultipleReturnsDefaultForMissingKeys(callable $factory): void
    {
        $cache = $factory();
        $cache->set('present', 'value');

        $this->assertSame(
            ['present' => 'value', 'absent' => 'fallback'],
            $this->toArray($cache->getMultiple(['present', 'absent'], 'fallback')),
        );
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('traitUsingBackends')]
    public function testDeleteMultipleRemovesEveryKey(callable $factory): void
    {
        $cache = $factory();
        $cache->setMultiple(['one' => 1, 'two' => 2, 'three' => 3]);

        $this->assertTrue($cache->deleteMultiple(['one', 'three']));

        $this->assertFalse($cache->has('one'));
        $this->assertFalse($cache->has('three'));
        $this->assertTrue($cache->has('two'));
    }

    /**
     * The trait preserves the order of the requested keys in the result,
     * independent of storage/insertion order.
     *
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('traitUsingBackends')]
    public function testGetMultiplePreservesRequestedKeyOrder(callable $factory): void
    {
        $cache = $factory();
        $cache->setMultiple(['a' => 1, 'b' => 2, 'c' => 3]);

        $this->assertSame(
            ['c', 'a', 'b'],
            array_keys($this->toArray($cache->getMultiple(['c', 'a', 'b']))),
        );
    }

    public function testEmptyBatchesAreNoOps(): void
    {
        $cache = new InMemoryCache();

        $this->assertTrue($cache->setMultiple([]));
        $this->assertTrue($cache->deleteMultiple([]));
        $this->assertSame([], $this->toArray($cache->getMultiple([])));
    }

    public function testSetMultipleReportsFailureButStillAttemptsEveryWrite(): void
    {
        $cache = new RecordingFailingCache();

        $this->assertFalse(
            $cache->setMultiple(['keep-one' => 1, 'fail-key' => 2, 'keep-two' => 3]),
            'setMultiple must return false when any underlying set() fails',
        );
        $this->assertSame(
            ['keep-one', 'fail-key', 'keep-two'],
            $cache->setAttempts,
            'every key must be attempted even after one fails (no short-circuit)',
        );
    }

    public function testSetMultipleReturnsTrueWhenEveryWriteSucceeds(): void
    {
        $cache = new RecordingFailingCache();

        $this->assertTrue($cache->setMultiple(['keep-one' => 1, 'keep-two' => 2]));
    }

    public function testDeleteMultipleReportsFailureButStillAttemptsEveryDelete(): void
    {
        $cache = new RecordingFailingCache();

        $this->assertFalse(
            $cache->deleteMultiple(['keep-one', 'fail-key', 'keep-two']),
            'deleteMultiple must return false when any underlying delete() fails',
        );
        $this->assertSame(['keep-one', 'fail-key', 'keep-two'], $cache->deleteAttempts);
    }

    /**
     * Normalise a PSR-16 iterable result into a plain array for assertions.
     *
     * @param iterable<string, mixed> $result
     *
     * @return array<string, mixed>
     */
    private function toArray(iterable $result): array
    {
        return is_array($result) ? $result : iterator_to_array($result);
    }
}
