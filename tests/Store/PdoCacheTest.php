<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\PdoCache;
use PDO;
use PHPUnit\Framework\TestCase;

final class PdoCacheTest extends TestCase
{
    private function createCache(string $tableName = 'phirewall_cache'): PdoCache
    {
        return new PdoCache(new PDO('sqlite::memory:'), $tableName);
    }

    // ── Basic CacheInterface operations ──────────────────────────────────

    public function testGetSetBasic(): void
    {
        $cache = $this->createCache();
        $cache->set('foo', 'bar');
        $this->assertSame('bar', $cache->get('foo'));
    }

    public function testGetReturnsDefaultForMissingKey(): void
    {
        $cache = $this->createCache();
        $this->assertNull($cache->get('missing'));
        $this->assertSame('default', $cache->get('missing', 'default'));
    }

    public function testSetWithTtl(): void
    {
        $cache = $this->createCache();
        $cache->set('expires', 'soon', 3600);
        $this->assertSame('soon', $cache->get('expires'));
    }

    public function testSetWithDateIntervalTtl(): void
    {
        $cache = $this->createCache();
        $cache->set('interval', 'value', new \DateInterval('PT1H'));
        $this->assertSame('value', $cache->get('interval'));
    }

    public function testExpiredKeyReturnsDefault(): void
    {
        $cache = $this->createCache();
        $cache->set('expired', 'old', -1);
        $this->assertNull($cache->get('expired'));
    }

    public function testDelete(): void
    {
        $cache = $this->createCache();
        $cache->set('foo', 'bar');
        $cache->delete('foo');
        $this->assertNull($cache->get('foo'));
    }

    public function testHas(): void
    {
        $cache = $this->createCache();
        $this->assertFalse($cache->has('foo'));
        $cache->set('foo', 'bar');
        $this->assertTrue($cache->has('foo'));
    }

    public function testHasReturnsFalseForExpired(): void
    {
        $cache = $this->createCache();
        $cache->set('expired', 'old', -1);
        $this->assertFalse($cache->has('expired'));
    }

    public function testClear(): void
    {
        $cache = $this->createCache();
        $cache->set('a', 1);
        $cache->set('b', 2);
        $cache->clear();
        $this->assertNull($cache->get('a'));
        $this->assertNull($cache->get('b'));
    }

    // ── Multiple operations ──────────────────────────────────────────────

    public function testGetMultiple(): void
    {
        $cache = $this->createCache();
        $cache->set('a', 1);
        $cache->set('b', 2);

        $result = $cache->getMultiple(['a', 'b', 'c'], 'default');
        $this->assertSame(['a' => 1, 'b' => 2, 'c' => 'default'], $result);
    }

    public function testSetMultiple(): void
    {
        $cache = $this->createCache();
        $cache->setMultiple(['x' => 10, 'y' => 20]);
        $this->assertSame(10, $cache->get('x'));
        $this->assertSame(20, $cache->get('y'));
    }

    public function testDeleteMultiple(): void
    {
        $cache = $this->createCache();
        $cache->set('a', 1);
        $cache->set('b', 2);
        $cache->deleteMultiple(['a', 'b']);
        $this->assertNull($cache->get('a'));
        $this->assertNull($cache->get('b'));
    }

    // ── CounterStoreInterface operations ─────────────────────────────────

    public function testIncrement(): void
    {
        $cache = $this->createCache();
        $this->assertSame(1, $cache->increment('counter', 60));
        $this->assertSame(2, $cache->increment('counter', 60));
        $this->assertSame(3, $cache->increment('counter', 60));
    }

    public function testIncrementSetsExpiryToWindowEnd(): void
    {
        $cache = $this->createCache();
        $cache->increment('counter', 60);

        $ttl = $cache->ttlRemaining('counter');
        // TTL should be at most 60 seconds (remainder of the current window)
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);
    }

    public function testTtlRemaining(): void
    {
        $cache = $this->createCache();
        $cache->set('key', 'val', 3600);

        $ttl = $cache->ttlRemaining('key');
        $this->assertGreaterThan(3590, $ttl);
        $this->assertLessThanOrEqual(3600, $ttl);
    }

    public function testTtlRemainingReturnsZeroForMissingKey(): void
    {
        $cache = $this->createCache();
        $this->assertSame(0, $cache->ttlRemaining('missing'));
    }

    public function testTtlRemainingReturnsZeroForNoExpiry(): void
    {
        $cache = $this->createCache();
        $cache->set('persistent', 'value');
        $this->assertSame(0, $cache->ttlRemaining('persistent'));
    }

    // ── Upsert / overwrite behavior ──────────────────────────────────────

    public function testOverwriteExistingKey(): void
    {
        $cache = $this->createCache();
        $cache->set('key', 'v1');
        $cache->set('key', 'v2');
        $this->assertSame('v2', $cache->get('key'));
    }

    // ── Complex values ───────────────────────────────────────────────────

    public function testStoresComplexValues(): void
    {
        $cache = $this->createCache();
        $data = ['nested' => ['array' => true], 'count' => 42];
        $cache->set('complex', $data);
        $this->assertSame($data, $cache->get('complex'));
    }

    public function testStoresNullValue(): void
    {
        $cache = $this->createCache();
        $cache->set('null-val', null);
        // null is a valid stored value; verify via has()
        $this->assertTrue($cache->has('null-val'));
    }

    // ── Table name validation ────────────────────────────────────────────

    public function testAutoCreatesTableWithCustomName(): void
    {
        $cache = $this->createCache('custom_table');
        $cache->set('test', 'value');
        $this->assertSame('value', $cache->get('test'));
    }

    public function testRejectsInvalidTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCache(new PDO('sqlite::memory:'), 'DROP TABLE; --');
    }

    public function testRejectsTableNameStartingWithDigit(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCache(new PDO('sqlite::memory:'), '1table');
    }

    public function testRejectsEmptyTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCache(new PDO('sqlite::memory:'), '');
    }

    public function testRejectsTableNameExceeding64Characters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCache(new PDO('sqlite::memory:'), str_repeat('a', 65));
    }

    public function testAcceptsTableNameExactly64Characters(): void
    {
        $cache = new PdoCache(new PDO('sqlite::memory:'), str_repeat('a', 64));
        $cache->set('key', 'value');
        $this->assertSame('value', $cache->get('key'));
    }

    public function testAcceptsTableNameStartingWithUnderscore(): void
    {
        $cache = new PdoCache(new PDO('sqlite::memory:'), '_my_cache');
        $cache->set('key', 'value');
        $this->assertSame('value', $cache->get('key'));
    }

    public function testRejectsTableNameWithSpecialCharacters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCache(new PDO('sqlite::memory:'), 'table-name');
    }

    // ── Edge cases for batch operations ────────────────────────────────

    public function testGetMultipleWithEmptyKeys(): void
    {
        $cache = $this->createCache();
        $result = $cache->getMultiple([]);
        $this->assertSame([], $result);
    }

    public function testGetMultipleFiltersExpiredEntries(): void
    {
        $cache = $this->createCache();
        $cache->set('fresh', 'yes', 3600);
        $cache->set('stale', 'no', -1);

        $result = $cache->getMultiple(['fresh', 'stale', 'missing'], 'default');
        $this->assertSame(['fresh' => 'yes', 'stale' => 'default', 'missing' => 'default'], $result);
    }

    public function testDeleteMultipleWithEmptyKeys(): void
    {
        $cache = $this->createCache();
        $this->assertTrue($cache->deleteMultiple([]));
    }

    // ── Increment edge cases ────────────────────────────────────────────

    public function testIncrementResetsExpiredCounter(): void
    {
        $cache = $this->createCache();
        // Set a key with a past expiry to simulate an expired window
        $cache->set('counter', 'ignored', -1);

        // Increment should start from 1 (expired entry ignored)
        $this->assertSame(1, $cache->increment('counter', 60));
    }

    // ── Deserialization safety ─────────────────────────────────────────

    public function testDeserializedObjectsAreIncomplete(): void
    {
        // Store a serialized stdClass via PdoCache
        $pdo = new PDO('sqlite::memory:');
        $directCache = new PdoCache($pdo);
        $directCache->set('obj', new \stdClass());

        $retrieved = $directCache->get('obj');
        // With allowed_classes=false, objects become __PHP_Incomplete_Class
        $this->assertNotInstanceOf(\stdClass::class, $retrieved);
    }

    // ── Integration: works as Phirewall cache backend ────────────────────

    public function testWorksAsPhirewallCacheBackend(): void
    {
        $cache = $this->createCache();
        $config = new \Flowd\Phirewall\Config($cache);
        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new \Flowd\Phirewall\Http\Firewall($config);
        $request = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $result1 = $firewall->decide($request);
        $this->assertTrue($result1->isPass());

        $result2 = $firewall->decide($request);
        $this->assertTrue($result2->isPass());

        $result3 = $firewall->decide($request);
        $this->assertSame(\Flowd\Phirewall\Http\Outcome::THROTTLED, $result3->outcome);
    }
}
