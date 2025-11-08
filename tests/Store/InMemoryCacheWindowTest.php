<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use PHPUnit\Framework\TestCase;

final class InMemoryCacheWindowTest extends TestCase
{
    public function testIncrementAlignsToFixedWindowAndRolloverResetsCount(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $key = 'k';
        $period = 1; // 1-second window for fast tests

        // First increment should create entry in current window
        $v1 = $inMemoryCache->increment($key, $period);
        $this->assertSame(1, $v1, 'First increment should return 1');
        $ttl1 = $inMemoryCache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(0, $ttl1);
        $this->assertLessThanOrEqual($period, $ttl1, 'TTL should not exceed the period');

        // Second increment within the same window should increase count
        $v2 = $inMemoryCache->increment($key, $period);
        $this->assertSame(2, $v2, 'Second increment within same window should return 2');

        // Advance time to cross the 1-second window boundary with a small safety margin
        $fakeClock->advance(1.15);

        // Next increment should roll over to the new window and reset count
        $v3 = $inMemoryCache->increment($key, $period);
        $this->assertSame(1, $v3, 'After window rollover, counter should reset to 1');

        $ttlAfterRollover = $inMemoryCache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttlAfterRollover, 'New window TTL should be close to full period (>=1)');
        $this->assertLessThanOrEqual($period, $ttlAfterRollover);
    }

    public function testTtlRemainingDecreasesOverTimeAndNeverNegative(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $key = 'k2';
        $period = 2;

        $inMemoryCache->increment($key, $period);
        $ttlStart = $inMemoryCache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttlStart);
        $this->assertLessThanOrEqual($period, $ttlStart);

        // Advance a bit and confirm TTL decreases
        $fakeClock->advance(0.3);
        $ttlMid = $inMemoryCache->ttlRemaining($key);
        $this->assertLessThanOrEqual($ttlStart, $ttlMid, 'TTL should decrease over time');

        // Advance more than the remaining TTL so it hits 0 (but never negative)
        $fakeClock->advance(2.0);
        $ttlEnd = $inMemoryCache->ttlRemaining($key);
        $this->assertSame(0, $ttlEnd, 'TTL should clamp to 0 after expiry');
    }
}
