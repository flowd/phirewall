<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\ApcuCache;
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
        $cache = new ApcuCache();
        $key = 'test:apcu:counter:' . uniqid('', true);
        $period = 2; // seconds

        $count1 = $cache->increment($key, $period);
        $count2 = $cache->increment($key, $period);
        self::assertSame(1, $count1);
        self::assertSame(2, $count2);

        $ttl = $cache->ttlRemaining($key);
        self::assertGreaterThanOrEqual(1, $ttl);
        self::assertLessThanOrEqual($period, $ttl);
    }

    public function testPsr16BasicSetGet(): void
    {
        $this->requireApcuOrSkip();
        $cache = new ApcuCache();
        $key = 'test:apcu:psr16:' . uniqid('', true);
        self::assertFalse($cache->has($key));
        self::assertSame('d', $cache->get($key, 'd'));
        self::assertTrue($cache->set($key, 'v', 5));
        self::assertTrue($cache->has($key));
        self::assertSame('v', $cache->get($key));
        self::assertTrue($cache->delete($key));
        self::assertFalse($cache->has($key));
    }
}
