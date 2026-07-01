<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\ApcuCache;
use Flowd\Phirewall\Store\InvalidCacheKeyException;
use PHPUnit\Framework\TestCase;

final class ApcuCacheTest extends TestCase
{
    private function requireApcuOrSkip(): void
    {
        if (!function_exists('apcu_enabled') || apcu_enabled() !== true) {
            $this->markTestSkipped('APCu is not enabled (require ext-apcu and apc.enable_cli=1).');
        }
    }

    public function testIncrementAndTtlRemainingFixedWindow(): void
    {
        $this->requireApcuOrSkip();
        $apcuCache = new ApcuCache();
        $key = 'test.apcu.counter.' . uniqid('', true);
        $period = 2; // seconds

        $count1 = $apcuCache->increment($key, $period);
        $count2 = $apcuCache->increment($key, $period);
        $this->assertSame(1, $count1);
        $this->assertSame(2, $count2);

        $ttl = $apcuCache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttl);
        $this->assertLessThanOrEqual($period, $ttl);
    }

    public function testPsr16BasicSetGet(): void
    {
        $this->requireApcuOrSkip();
        $apcuCache = new ApcuCache();
        $key = 'test.apcu.psr16.' . uniqid('', true);
        $this->assertFalse($apcuCache->has($key));
        $this->assertSame('d', $apcuCache->get($key, 'd'));
        $this->assertTrue($apcuCache->set($key, 'v', 5));
        $this->assertTrue($apcuCache->has($key));
        $this->assertSame('v', $apcuCache->get($key));
        $this->assertTrue($apcuCache->delete($key));
        $this->assertFalse($apcuCache->has($key));
    }

    public function testStoresKeysUnderNamespace(): void
    {
        $this->requireApcuOrSkip();
        $namespace = 'test.apcu.ns.' . uniqid('', true) . ':';
        $apcuCache = new ApcuCache($namespace);
        $key = 'scoped.key';

        $this->assertTrue($apcuCache->set($key, 'v', 30));
        $this->assertTrue(apcu_exists($namespace . $key));
        $this->assertFalse(apcu_exists($key));
        $this->assertSame('v', $apcuCache->get($key));

        $apcuCache->clear();
    }

    public function testDifferentNamespacesDoNotCollide(): void
    {
        $this->requireApcuOrSkip();
        $suffix = uniqid('', true);
        $cacheA = new ApcuCache('test.apcu.nsA.' . $suffix . ':');
        $cacheB = new ApcuCache('test.apcu.nsB.' . $suffix . ':');
        $key = 'shared.key';

        $cacheA->set($key, 'a', 30);
        $cacheB->set($key, 'b', 30);

        $this->assertSame('a', $cacheA->get($key));
        $this->assertSame('b', $cacheB->get($key));

        $cacheA->clear();
        $cacheB->clear();
    }

    public function testClearRemovesOnlyOwnNamespace(): void
    {
        $this->requireApcuOrSkip();
        $suffix = uniqid('', true);
        $ownCache = new ApcuCache('test.apcu.own.' . $suffix . ':');
        $foreignCache = new ApcuCache('test.apcu.foreign.' . $suffix . ':');
        $unprefixedKey = 'test.apcu.bare.' . $suffix;

        $ownCache->set('key', 'own', 30);
        $foreignCache->set('key', 'foreign', 30);
        apcu_store($unprefixedKey, 'bare', 30);

        $this->assertTrue($ownCache->clear());

        $this->assertFalse($ownCache->has('key'));
        $this->assertSame('foreign', $foreignCache->get('key'));
        $this->assertTrue(apcu_exists($unprefixedKey));

        $foreignCache->clear();
        apcu_delete($unprefixedKey);
    }

    public function testIncrementAndTtlRemainingUseNamespace(): void
    {
        $this->requireApcuOrSkip();
        $namespace = 'test.apcu.nsinc.' . uniqid('', true) . ':';
        $apcuCache = new ApcuCache($namespace);
        $key = 'counter';
        $period = 2;

        $this->assertSame(1, $apcuCache->increment($key, $period));
        $this->assertSame(2, $apcuCache->increment($key, $period));
        $this->assertTrue(apcu_exists($namespace . $key));
        $this->assertTrue(apcu_exists($namespace . $key . '::exp'));
        $this->assertFalse(apcu_exists($key));

        $ttl = $apcuCache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttl);
        $this->assertLessThanOrEqual($period, $ttl);

        $apcuCache->clear();
    }

    public function testRejectsKeyWithReservedCharacter(): void
    {
        $this->requireApcuOrSkip();
        $this->expectException(InvalidCacheKeyException::class);
        (new ApcuCache())->get('bad:key');
    }

    public function testGetMultipleRejectsNonStringKey(): void
    {
        $this->requireApcuOrSkip();
        $this->expectException(InvalidCacheKeyException::class);
        /** @phpstan-ignore-next-line intentionally invalid: non-string key */
        (new ApcuCache())->getMultiple(['valid', 42]);
    }
}
