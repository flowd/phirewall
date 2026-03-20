<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the sliding window throttle feature.
 *
 * The sliding window uses a weighted average of the current and previous
 * fixed-window counters to prevent the "double burst" problem at window
 * boundaries.
 *
 * Estimate formula: previousCount * (1 - weight) + currentCount
 * where weight = elapsed / period
 */
final class SlidingThrottleTest extends TestCase
{
    /**
     * Create a test stack with a deterministic clock.
     *
     * The start time (1_200_000_000.0) is divisible by 60, making window
     * boundary calculations straightforward for a 60-second period.
     *
     * @return array{FakeClock, InMemoryCache, Config}
     */
    private function createStack(): array
    {
        $fakeClock = new FakeClock(1_200_000_000.0);
        $inMemoryCache = new InMemoryCache($fakeClock);
        $config = new Config($inMemoryCache, clock: $fakeClock);

        return [$fakeClock, $inMemoryCache, $config];
    }

    /**
     * At the start of a window (weight=0), the sliding throttle should allow
     * exactly `limit` requests and then block the next one.
     */
    public function testSlidingThrottleAllowsUpToLimitThenBlocks(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 10;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d should pass', $i));
        }

        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'Request after limit should be throttled');
    }

    /**
     * The key sliding window test: demonstrate that a burst at a window
     * boundary is caught.
     *
     * Scenario:
     *   - Make 10 requests at T=59s (near the end of window 0)
     *   - Advance to T=61s (just past the boundary into window 1)
     *   - Make 1 request
     *
     * Sliding estimate: previousCount * (1 - weight) + currentCount
     *   = 10 * (1 - 1/60) + 1
     *   = 10 * (59/60) + 1
     *   ≈ 10.83
     *   > 10 (the limit)
     *   → THROTTLED
     */
    public function testSlidingWindowCatchesBurstAtBoundary(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 10;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Advance to T=59s (near end of window 0)
        $clock->advance(59.0);

        // Make 10 requests (fills the limit exactly)
        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d at T=59s should pass', $i));
        }

        // Advance to T=61s (1 second into window 1)
        $clock->advance(2.0);

        // With sliding window, the estimate should exceed the limit
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'Sliding window should catch burst at boundary');
    }

    /**
     * Demonstrate the double-burst problem with fixed windows.
     *
     * Same scenario as testSlidingWindowCatchesBurstAtBoundary but using
     * the fixed-window add() method. The request at T=61s passes because the
     * fixed window counter has reset to zero.
     */
    public function testFixedWindowAllowsBurstAtBoundaryForComparison(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 10;
        $period = 60;
        $config->throttles->add('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Advance to T=59s (near end of window 0)
        $clock->advance(59.0);

        // Make 10 requests (fills the limit exactly)
        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d at T=59s should pass', $i));
        }

        // Advance to T=61s (1 second into window 1, fixed counter resets)
        $clock->advance(2.0);

        // With fixed window, the counter is fresh; this request passes
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::PASS, $result->outcome, 'Fixed window allows burst at boundary (double-burst problem)');
    }

    /**
     * Two different IPs should have isolated sliding window counters.
     * Exhausting the limit for one IP should not affect the other.
     */
    public function testDifferentKeysAreIsolated(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 5;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $requestA = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $requestB = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']);

        // Exhaust the limit for IP A
        for ($i = 0; $i < $limit; ++$i) {
            $this->assertSame(Outcome::PASS, $firewall->decide($requestA)->outcome);
        }

        $this->assertSame(Outcome::THROTTLED, $firewall->decide($requestA)->outcome, 'IP A should be throttled');

        // IP B should still be fully available
        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($requestB);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('IP B request #%d should pass', $i));
        }
    }

    /**
     * After filling the limit and advancing past two full periods, the
     * previous window counter should have expired and new requests should
     * pass again.
     */
    public function testSlidingWindowReleasesAfterTimePasses(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 5;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Fill the limit
        for ($i = 0; $i < $limit; ++$i) {
            $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);
        }

        $this->assertSame(Outcome::THROTTLED, $firewall->decide($serverRequest)->outcome);

        // Advance past 2 full periods so the previous window data has expired
        $clock->advance(2.0 * $period + 1.0);

        // Requests should pass again
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::PASS, $firewallResult->outcome, 'Requests should pass after enough time has elapsed');
    }

    /**
     * When throttled, the Retry-After header must be present and its value
     * should be between 1 and the configured period.
     */
    public function testSlidingThrottleRetryAfterHeader(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 3;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Exhaust the limit
        for ($i = 0; $i < $limit; ++$i) {
            $firewall->decide($serverRequest);
        }

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertArrayHasKey('Retry-After', $firewallResult->headers);

        $retryAfter = (int) $firewallResult->headers['Retry-After'];
        $this->assertGreaterThanOrEqual(1, $retryAfter);
        $this->assertLessThanOrEqual($period, $retryAfter);
    }

    /**
     * With rate limit headers enabled, a throttled response should include
     * X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset.
     */
    public function testSlidingThrottleWithRateLimitHeaders(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 3;
        $period = 60;
        $config->enableRateLimitHeaders();
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Exhaust the limit
        for ($i = 0; $i < $limit; ++$i) {
            $firewall->decide($serverRequest);
        }

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        $this->assertArrayHasKey('X-RateLimit-Limit', $firewallResult->headers);
        $this->assertArrayHasKey('X-RateLimit-Remaining', $firewallResult->headers);
        $this->assertArrayHasKey('X-RateLimit-Reset', $firewallResult->headers);

        $this->assertSame((string) $limit, $firewallResult->headers['X-RateLimit-Limit']);
        $this->assertSame('0', $firewallResult->headers['X-RateLimit-Remaining']);

        $reset = (int) $firewallResult->headers['X-RateLimit-Reset'];
        $this->assertGreaterThanOrEqual(1, $reset);
        $this->assertLessThanOrEqual($period, $reset);
    }

    /**
     * Verify that the sliding window weight decays over time within the
     * next window.
     *
     * Scenario:
     *   - Make 10 requests at T=59s (end of window 0, previousCount = 10)
     *   - Advance to T=90s (30s into window 1, weight = 30/60 = 0.5)
     *   - Make 1 request (currentCount = 1)
     *
     * Estimate: 10 * (1 - 0.5) + 1 = 5 + 1 = 6 ≤ 10 → PASS
     */
    public function testSlidingWindowWeightDecaysOverTime(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 10;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Advance to T=59s (near end of window 0)
        $clock->advance(59.0);

        // Make 10 requests to fill window 0
        for ($i = 0; $i < $limit; ++$i) {
            $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome, sprintf('Request #%d should pass', $i));
        }

        // Advance to T=90s (30 seconds into window 1)
        $clock->advance(31.0);

        // Estimate: 10 * (1 - 30/60) + 1 = 10 * 0.5 + 1 = 6 ≤ 10 → PASS
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::PASS, $firewallResult->outcome, 'Weight decay should allow the request to pass');
    }

    /**
     * When the key extractor returns null, the throttle rule should be
     * skipped entirely and the request should always pass.
     */
    public function testNullKeySkipsThrottle(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 1;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // All requests should pass regardless of the limit
        for ($i = 0; $i < 20; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d should pass when key is null', $i));
        }
    }

    /**
     * Verify that the sliding flag can be set via the ThrottleRule constructor
     * and addRule() method directly, bypassing the sliding() convenience method.
     */
    public function testSlidingFlagViaAddRule(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 10;
        $period = 60;

        $keyExtractor = new ClosureKeyExtractor(
            fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null
        );
        $throttleRule = new ThrottleRule('ip-limit', $limit, $period, $keyExtractor, sliding: true);

        $this->assertTrue($throttleRule->isSliding(), 'ThrottleRule should report sliding as true');

        $config->throttles->addRule($throttleRule);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Advance to T=59s (near end of window 0)
        $clock->advance(59.0);

        // Fill the limit in window 0
        for ($i = 0; $i < $limit; ++$i) {
            $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);
        }

        // Advance to T=61s (1 second into window 1)
        $clock->advance(2.0);

        // Sliding window should catch the burst just like the sliding() method
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'addRule with sliding: true should behave like sliding()');
    }

    /**
     * At exactly the window boundary (elapsed = 0), the previous window
     * multiplier (1 - weight) equals 1.0, so the full previous count carries over.
     *
     * Scenario:
     *   - Make 5 requests at T=0 (fills limit in window 0, previousCount = 5)
     *   - Advance exactly one period (60s) to the next window boundary
     *   - elapsed = 0, weight = 0/60 = 0
     *   - Make 1 request (currentCount = 1)
     *
     * Estimate: 5 * (1 - 0) + 1 = 5 + 1 = 6 > 5 → THROTTLED
     */
    public function testSlidingWindowAtExactBoundary(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 5;
        $period = 60;
        $config->throttles->sliding('ip-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Fill the limit in window 0
        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d should pass', $i));
        }

        // Advance exactly to the next window boundary
        $clock->advance((float) $period);

        // At elapsed=0: weight=0, estimate = previousCount * 1.0 + currentCount = 5 + 1 = 6 > 5
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'Request at exact boundary should be throttled (full previous weight)');
    }

    /**
     * Two different sliding rules with different limits applied to the same
     * request. The stricter rule should trigger first.
     *
     * Scenario:
     *   - Rule 1: 'api-limit', limit=5, period=60
     *   - Rule 2: 'search-limit', limit=3, period=60
     *   - Send 3 requests → both rules pass
     *   - Send request 4 → 'search-limit' triggers (count=4 > limit=3)
     */
    public function testMultipleSlidingRulesOnSameRequest(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $keyExtractor = fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null;

        $config->throttles->sliding('api-limit', 5, 60, $keyExtractor);
        $config->throttles->sliding('search-limit', 3, 60, $keyExtractor);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // First 3 requests pass both rules
        for ($i = 0; $i < 3; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d should pass both rules', $i));
        }

        // Request 4: api-limit allows (4 ≤ 5) but search-limit triggers (4 > 3)
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'search-limit should trigger throttle');
        $this->assertSame('search-limit', $result->rule, 'The stricter rule name should appear in the result');
    }

    /**
     * One fixed-window rule and one sliding-window rule on the same config.
     * The sliding window should catch a boundary burst that the fixed window misses.
     *
     * Scenario:
     *   - Fixed rule: 'fixed-limit', limit=10, period=60
     *   - Sliding rule: 'sliding-limit', limit=10, period=60
     *   - Make 10 requests at T=59s (near end of window 0)
     *   - Advance to T=61s (1s into window 1)
     *   - Send 1 request:
     *     - Fixed window: counter reset, count=1 ≤ 10 → PASS
     *     - Sliding window: estimate = 10*(59/60) + 1 ≈ 10.83, ceil=11 > 10 → THROTTLED
     */
    public function testMixedSlidingAndFixedThrottleRules(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $keyExtractor = fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null;

        // Fixed rule first, then sliding rule (order matters for evaluation)
        $config->throttles->add('fixed-limit', 10, 60, $keyExtractor);
        $config->throttles->sliding('sliding-limit', 10, 60, $keyExtractor);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Advance to T=59s (near end of window 0)
        $clock->advance(59.0);

        // Fill both limits with 10 requests
        for ($i = 0; $i < 10; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d at T=59s should pass', $i));
        }

        // Advance to T=61s (1 second into window 1)
        $clock->advance(2.0);

        // Fixed window resets (count=1 ≤ 10 → passes), but sliding catches the burst
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'Sliding rule should catch burst even though fixed rule allows it');
        $this->assertSame('sliding-limit', $result->rule, 'The sliding rule should be the one that triggers');
    }

    /**
     * Verify sliding window correctness with a very small period (1 second)
     * to exercise float precision in the weight calculation.
     *
     * Scenario:
     *   - period=1, limit=5
     *   - Make 5 requests at T=0 → all pass
     *   - Request 6 → THROTTLED (counter stored as 6 due to pre-check increment)
     *   - Advance 1.5s to T=1.5 (0.5s into new window, weight=0.5)
     *   - Make 1 request:
     *     estimate = 6 * (1 - 0.5) + 1 = 6 * 0.5 + 1 = 4.0
     *     ceil(4.0) = 4 ≤ 5 → PASS
     */
    public function testSlidingWindowWithSmallPeriod(): void
    {
        [$clock, $cache, $config] = $this->createStack();

        $limit = 5;
        $period = 1;
        $config->throttles->sliding('fast-limit', $limit, $period, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Make 5 requests at T=0 → all pass
        for ($i = 0; $i < $limit; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertSame(Outcome::PASS, $result->outcome, sprintf('Request #%d should pass', $i));
        }

        // Request 6 → THROTTLED
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome, 'Request exceeding limit should be throttled');

        // Advance 1.5 seconds (0.5s into the second window)
        $clock->advance(1.5);

        // estimate = 6 * (1 - 0.5) + 1 = 4.0, ceil(4) = 4 ≤ 5 → PASS
        $result = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::PASS, $result->outcome, 'Request should pass after weight decay with small period');
    }
}
