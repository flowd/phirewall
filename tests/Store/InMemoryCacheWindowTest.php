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
        $clock = new FakeClock();
        $cache = new InMemoryCache($clock);
        $key = 'k';
        $period = 1; // 1-second window for fast tests

        // First increment should create entry in current window
        $v1 = $cache->increment($key, $period);
        $this->assertSame(1, $v1, 'First increment should return 1');
        $ttl1 = $cache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(0, $ttl1);
        $this->assertLessThanOrEqual($period, $ttl1, 'TTL should not exceed the period');

        // Second increment within the same window should increase count
        $v2 = $cache->increment($key, $period);
        $this->assertSame(2, $v2, 'Second increment within same window should return 2');

        // Advance time to cross the 1-second window boundary with a small safety margin
        $clock->advance(1.15);

        // Next increment should roll over to the new window and reset count
        $v3 = $cache->increment($key, $period);
        $this->assertSame(1, $v3, 'After window rollover, counter should reset to 1');

        $ttlAfterRollover = $cache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttlAfterRollover, 'New window TTL should be close to full period (>=1)');
        $this->assertLessThanOrEqual($period, $ttlAfterRollover);
    }

    public function testTtlRemainingDecreasesOverTimeAndNeverNegative(): void
    {
        $clock = new FakeClock();
        $cache = new InMemoryCache($clock);
        $key = 'k2';
        $period = 2;

        $cache->increment($key, $period);
        $ttlStart = $cache->ttlRemaining($key);
        $this->assertGreaterThanOrEqual(1, $ttlStart);
        $this->assertLessThanOrEqual($period, $ttlStart);

        // Advance a bit and confirm TTL decreases
        $clock->advance(0.3);
        $ttlMid = $cache->ttlRemaining($key);
        $this->assertLessThanOrEqual($ttlStart, $ttlMid, 'TTL should decrease over time');

        // Advance more than the remaining TTL so it hits 0 (but never negative)
        $clock->advance(2.0);
        $ttlEnd = $cache->ttlRemaining($key);
        $this->assertSame(0, $ttlEnd, 'TTL should clamp to 0 after expiry');
    }
}
