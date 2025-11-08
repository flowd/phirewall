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
        $apcuCache = new ApcuCache();
        $key = 'test:apcu:counter:' . uniqid('', true);
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
        $key = 'test:apcu:psr16:' . uniqid('', true);
        $this->assertFalse($apcuCache->has($key));
        $this->assertSame('d', $apcuCache->get($key, 'd'));
        $this->assertTrue($apcuCache->set($key, 'v', 5));
        $this->assertTrue($apcuCache->has($key));
        $this->assertSame('v', $apcuCache->get($key));
        $this->assertTrue($apcuCache->delete($key));
        $this->assertFalse($apcuCache->has($key));
    }
}
