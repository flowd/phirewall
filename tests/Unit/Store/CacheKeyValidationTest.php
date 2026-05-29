<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\CounterStoreInterface;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Store\InvalidCacheKeyException;
use Flowd\Phirewall\Store\PdoCache;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

/**
 * PSR-16 key validation shared by every cache backend.
 *
 * The character matrix is exercised once through {@see InMemoryCache} because
 * the rules live in the shared {@see \Flowd\Phirewall\Store\KeyValidationTrait};
 * the backend-parameterised tests then confirm the trait is wired into every
 * PSR-16 method of each concrete backend.
 */
#[CoversClass(InvalidCacheKeyException::class)]
final class CacheKeyValidationTest extends TestCase
{
    /**
     * @return iterable<string, array{0: callable(): CacheInterface}>
     */
    public static function backendFactories(): iterable
    {
        yield 'InMemoryCache' => [static fn(): CacheInterface => new InMemoryCache()];
        yield 'PdoCache (sqlite)' => [static fn(): CacheInterface => new PdoCache(new PDO('sqlite::memory:'))];
    }

    /**
     * @return list<array{0: string}>
     */
    public static function reservedCharacterKeys(): array
    {
        return array_map(
            static fn(string $char): array => ['prefix' . $char . 'suffix'],
            ['{', '}', '(', ')', '/', '\\', '@', ':'],
        );
    }

    /**
     * @return iterable<array{0: string}>
     */
    public static function controlAndWhitespaceKeys(): iterable
    {
        yield ['has space'];
        yield ["tab\tinside"];
        yield ["new\nline"];
        yield ["null\0byte"];
        yield ["carriage\rreturn"];
        yield ["delete\x7fchar"];
    }

    // ── Per-backend wiring: every PSR-16 method validates its key ─────────

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testGetRejectsReservedKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        $factory()->get('bad:key');
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testSetRejectsReservedKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        $factory()->set('bad:key', 'value');
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testHasRejectsReservedKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        $factory()->has('bad:key');
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testDeleteRejectsReservedKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        $factory()->delete('bad:key');
    }

    /**
     * The counter API ({@see CounterStoreInterface}) must reject the same keys
     * as the PSR-16 surface so reserved/control characters can never reach
     * storage through a different door.
     *
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testIncrementRejectsReservedKey(callable $factory): void
    {
        $cache = $factory();
        $this->assertInstanceOf(CounterStoreInterface::class, $cache);

        $this->expectException(InvalidCacheKeyException::class);
        $cache->increment('bad:key', 60);
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testTtlRemainingRejectsReservedKey(callable $factory): void
    {
        $cache = $factory();
        $this->assertInstanceOf(CounterStoreInterface::class, $cache);

        $this->expectException(InvalidCacheKeyException::class);
        $cache->ttlRemaining('bad:key');
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testGetMultipleRejectsNonStringKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        /** @phpstan-ignore-next-line intentionally invalid: non-string key */
        $factory()->getMultiple(['valid', 42]);
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testDeleteMultipleRejectsNonStringKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        /** @phpstan-ignore-next-line intentionally invalid: non-string key */
        $factory()->deleteMultiple([42]);
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testSetMultipleRejectsNonStringKey(callable $factory): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        $factory()->setMultiple([5 => 'value']);
    }

    /**
     * @param callable(): CacheInterface $factory
     */
    #[DataProvider('backendFactories')]
    public function testValidKeysRoundTrip(callable $factory): void
    {
        $cache = $factory();
        $key = 'phirewall.throttle.rule_name.' . str_repeat('a', 64); // > 64 chars: must be supported

        $this->assertTrue($cache->set($key, 'value'));
        $this->assertTrue($cache->has($key));
        $this->assertSame('value', $cache->get($key));
        $this->assertTrue($cache->delete($key));
    }

    // ── Shared character matrix (exercised through InMemoryCache) ─────────

    #[DataProvider('reservedCharacterKeys')]
    public function testReservedCharactersAreRejected(string $key): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        (new InMemoryCache())->set($key, 'value');
    }

    #[DataProvider('controlAndWhitespaceKeys')]
    public function testControlAndWhitespaceCharactersAreRejected(string $key): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        (new InMemoryCache())->set($key, 'value');
    }

    public function testEmptyKeyIsRejected(): void
    {
        $this->expectException(InvalidCacheKeyException::class);
        (new InMemoryCache())->set('', 'value');
    }

    public function testValidCharacterSetIsAccepted(): void
    {
        $cache = new InMemoryCache();
        $key = 'AZaz09._-'; // dash is not reserved by PSR-16

        $this->assertTrue($cache->set($key, 'value'));
        $this->assertSame('value', $cache->get($key));
    }

    public function testValidationRejectsBeforeAnyWriteInSetMultiple(): void
    {
        $cache = new InMemoryCache();

        try {
            $cache->setMultiple(['good_key' => 1, 5 => 2]);
            $this->fail('Expected InvalidCacheKeyException was not thrown.');
        } catch (InvalidCacheKeyException) {
            // The earlier valid key must not have been written: validation
            // completes for the whole batch before any value is stored.
            $this->assertFalse($cache->has('good_key'));
        }
    }

    public function testExceptionImplementsPsr16Marker(): void
    {
        $exception = new InvalidCacheKeyException('boom');

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }
}
