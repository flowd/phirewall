<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use PHPUnit\Framework\TestCase;

final class ConcurrentSequenceTest extends TestCase
{
    public function testInterleavedIncrementsAreIndependentPerKeyAndMonotonic(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $period = 2; // seconds
        $a = 'a';
        $b = 'b';

        // Interleave increments across two keys
        $this->assertSame(1, $inMemoryCache->increment($a, $period));
        $this->assertSame(1, $inMemoryCache->increment($b, $period));
        $this->assertSame(2, $inMemoryCache->increment($a, $period));
        $this->assertSame(2, $inMemoryCache->increment($b, $period));
        $this->assertSame(3, $inMemoryCache->increment($a, $period));
        $this->assertSame(3, $inMemoryCache->increment($b, $period));

        // TTLs should be within [0, period] and roughly similar as both started in same window
        $ttlA = $inMemoryCache->ttlRemaining($a);
        $ttlB = $inMemoryCache->ttlRemaining($b);
        $this->assertGreaterThanOrEqual(0, $ttlA);
        $this->assertGreaterThanOrEqual(0, $ttlB);
        $this->assertLessThanOrEqual($period, $ttlA);
        $this->assertLessThanOrEqual($period, $ttlB);

        // Advance a small amount; TTLs should not increase and counts continue monotonic
        $fakeClock->advance(0.2);
        $this->assertLessThanOrEqual($ttlA, $inMemoryCache->ttlRemaining($a));
        $this->assertLessThanOrEqual($ttlB, $inMemoryCache->ttlRemaining($b));
        $this->assertSame(4, $inMemoryCache->increment($a, $period));
        $this->assertSame(4, $inMemoryCache->increment($b, $period));
    }

    public function testNearBoundaryInterleavingResetsCleanlyAfterRollover(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $period = 1; // short window to cross quickly
        $k1 = 'k1';
        $k2 = 'k2';

        // Prime counts inside the first window
        $this->assertSame(1, $inMemoryCache->increment($k1, $period));
        $this->assertSame(1, $inMemoryCache->increment($k2, $period));

        $ttl1Before = $inMemoryCache->ttlRemaining($k1);
        $ttl2Before = $inMemoryCache->ttlRemaining($k2);
        $this->assertGreaterThanOrEqual(0, $ttl1Before);
        $this->assertGreaterThanOrEqual(0, $ttl2Before);
        $this->assertLessThanOrEqual($period, $ttl1Before);
        $this->assertLessThanOrEqual($period, $ttl2Before);

        // Advance just over the boundary to force rollover
        $fakeClock->advance(1.1) ;

        // After the window rolls over, first increments should reset to 1 for both keys, regardless of interleaving
        $this->assertSame(1, $inMemoryCache->increment($k1, $period));
        $ttl1After = $inMemoryCache->ttlRemaining($k1);
        $this->assertGreaterThanOrEqual(1, $ttl1After);
        $this->assertLessThanOrEqual($period, $ttl1After);

        $this->assertSame(1, $inMemoryCache->increment($k2, $period));
        $ttl2After = $inMemoryCache->ttlRemaining($k2);
        $this->assertGreaterThanOrEqual(1, $ttl2After);
        $this->assertLessThanOrEqual($period, $ttl2After);

        // And further increments continue from there
        $this->assertSame(2, $inMemoryCache->increment($k1, $period));
        $this->assertSame(2, $inMemoryCache->increment($k2, $period));
    }

    public function testTtlDoesNotIncreaseWithinSameWindow(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $key = 'stable-ttl';
        $period = 2;

        $inMemoryCache->increment($key, $period);
        $ttlStart = $inMemoryCache->ttlRemaining($key);
        $fakeClock->advance(0.15);
        $ttlMid = $inMemoryCache->ttlRemaining($key);
        $fakeClock->advance(0.15);
        $ttlMid2 = $inMemoryCache->ttlRemaining($key);

        // TTL should be non-increasing within the window
        $this->assertLessThanOrEqual($ttlStart, $ttlMid);
        $this->assertLessThanOrEqual($ttlMid, $ttlMid2);
    }
}
