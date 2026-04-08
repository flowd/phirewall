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
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class DynamicThrottleTest extends TestCase
{
    /**
     * Create a Config with a deterministic clock to avoid flaky time-boundary issues.
     */
    private function createConfig(): Config
    {
        $fakeClock = new FakeClock(1_200_000_000.0);
        $inMemoryCache = new InMemoryCache($fakeClock);

        return new Config($inMemoryCache, clock: $fakeClock);
    }

    /**
     * Backward compatibility: static integer values for limit and period still work.
     */
    public function testStaticLimitStillWorks(): void
    {
        $config = $this->createConfig();
        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    /**
     * A closure-based limit returns different values depending on the request.
     * Admin users get a higher limit (10) while regular users get a lower limit (2).
     */
    public function testDynamicLimitViaClosure(): void
    {
        $config = $this->createConfig();

        $dynamicLimit = fn(ServerRequestInterface $serverRequest): int =>
            $serverRequest->getHeaderLine('X-User-Role') === 'admin' ? 10 : 2;

        $config->throttles->add(
            'role-based',
            $dynamicLimit,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // Regular user: limit of 2
        $regularRequest = $serverRequest->withHeader('X-User-Role', 'user');
        $this->assertTrue($firewall->decide($regularRequest)->isPass());
        $this->assertTrue($firewall->decide($regularRequest)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($regularRequest)->outcome);

        // Admin user from a different IP: limit of 10
        // Use a different IP so counters don't overlap with the regular user
        $adminServerRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $adminServerRequest = $adminServerRequest->withHeader('X-User-Role', 'admin');

        for ($i = 0; $i < 10; ++$i) {
            $this->assertTrue(
                $firewall->decide($adminServerRequest)->isPass(),
                sprintf('Admin request #%d should pass', $i)
            );
        }

        // The 11th request should be throttled
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($adminServerRequest)->outcome);
    }

    /**
     * A closure-based period returns different time windows depending on the request.
     */
    public function testDynamicPeriodViaClosure(): void
    {
        $config = $this->createConfig();

        $dynamicPeriod = fn(ServerRequestInterface $serverRequest): int =>
            $serverRequest->getHeaderLine('X-Tier') === 'premium' ? 10 : 60;

        $config->throttles->add(
            'tier-based',
            2,
            $dynamicPeriod,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // A premium user still gets throttled after exceeding the limit
        $premiumRequest = $serverRequest->withHeader('X-Tier', 'premium');
        $this->assertTrue($firewall->decide($premiumRequest)->isPass());
        $this->assertTrue($firewall->decide($premiumRequest)->isPass());

        $firewallResult = $firewall->decide($premiumRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        // The Retry-After should reflect the shorter premium period (max 10 seconds)
        $retryAfter = (int) ($firewallResult->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retryAfter);
        $this->assertLessThanOrEqual(10, $retryAfter);
    }

    /**
     * The deprecated $config->throttle() method also accepts closure-based limits.
     */
    public function testDeprecatedThrottleAcceptsDynamicLimit(): void
    {
        $config = $this->createConfig();

        $dynamicLimit = fn(ServerRequestInterface $serverRequest): int => 3;

        $config->throttle(
            'deprecated-dynamic',
            $dynamicLimit,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    /**
     * Rate limit headers reflect the resolved dynamic limit value.
     */
    public function testDynamicLimitReturnsCorrectRateLimitHeaders(): void
    {
        $config = $this->createConfig();
        $config->enableRateLimitHeaders();

        $dynamicLimit = fn(ServerRequestInterface $serverRequest): int => 5;

        $config->throttles->add(
            'header-check',
            $dynamicLimit,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // First request should pass and have correct rate limit headers
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('5', $firewallResult->headers['X-RateLimit-Limit'] ?? null);
        $this->assertSame('4', $firewallResult->headers['X-RateLimit-Remaining'] ?? null);

        // Exhaust remaining requests
        for ($i = 0; $i < 4; ++$i) {
            $firewall->decide($serverRequest);
        }

        // Sixth request should be throttled with correct limit header
        $throttledResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $throttledResult->outcome);
        $this->assertSame('5', $throttledResult->headers['X-RateLimit-Limit'] ?? null);
        $this->assertSame('0', $throttledResult->headers['X-RateLimit-Remaining'] ?? null);
    }

    /**
     * Unit test for ThrottleRule::resolveLimit() and ThrottleRule::resolvePeriod()
     * with both static int and closure inputs.
     */
    public function testResolveMethodsOnThrottleRule(): void
    {
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        // Static int values
        $staticRule = new ThrottleRule('static', 100, 30, $keyExtractor);
        $this->assertSame(100, $staticRule->resolveLimit($serverRequest));
        $this->assertSame(30, $staticRule->resolvePeriod($serverRequest));

        // Closure values
        $dynamicLimitClosure = fn(ServerRequestInterface $serverRequest): int => 42;
        $dynamicPeriodClosure = fn(ServerRequestInterface $serverRequest): int => 120;
        $dynamicRule = new ThrottleRule('dynamic', $dynamicLimitClosure, $dynamicPeriodClosure, $keyExtractor);
        $this->assertSame(42, $dynamicRule->resolveLimit($serverRequest));
        $this->assertSame(120, $dynamicRule->resolvePeriod($serverRequest));

        // Closure that depends on request content
        $requestDependentLimit = fn(ServerRequestInterface $serverRequest): int =>
            $serverRequest->getHeaderLine('X-User-Role') === 'admin' ? 1000 : 10;
        $requestDependentRule = new ThrottleRule('request-dependent', $requestDependentLimit, 60, $keyExtractor);

        $this->assertSame(10, $requestDependentRule->resolveLimit($serverRequest));
        $adminRequest = $serverRequest->withHeader('X-User-Role', 'admin');
        $this->assertSame(1000, $requestDependentRule->resolveLimit($adminRequest));
    }

    /**
     * A static negative limit should throw an InvalidArgumentException at construction time.
     */
    public function testNegativeStaticLimitThrowsException(): void
    {
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('static limit must be non-negative');
        new ThrottleRule('negative-static', -1, 60, $keyExtractor);
    }

    /**
     * A static period of zero should throw an InvalidArgumentException at construction time.
     */
    public function testZeroStaticPeriodThrowsException(): void
    {
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('static period must be >= 1');
        new ThrottleRule('zero-period-static', 10, 0, $keyExtractor);
    }

    /**
     * A static negative period should throw an InvalidArgumentException at construction time.
     */
    public function testNegativeStaticPeriodThrowsException(): void
    {
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('static period must be >= 1');
        new ThrottleRule('negative-period-static', 10, -5, $keyExtractor);
    }

    /**
     * A closure returning a negative limit should throw a RuntimeException.
     */
    public function testNegativeDynamicLimitThrowsException(): void
    {
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        $negativeLimitClosure = fn(ServerRequestInterface $serverRequest): int => -1;
        $throttleRule = new ThrottleRule('negative-limit', $negativeLimitClosure, 60, $keyExtractor);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('dynamic limit must be non-negative');
        $throttleRule->resolveLimit($serverRequest);
    }

    /**
     * A closure returning 0 for the period should throw a RuntimeException.
     */
    public function testZeroPeriodDynamicThrowsException(): void
    {
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $keyExtractor = new ClosureKeyExtractor(fn($request): string => '127.0.0.1');

        $zeroPeriodClosure = fn(ServerRequestInterface $serverRequest): int => 0;
        $throttleRule = new ThrottleRule('zero-period', 10, $zeroPeriodClosure, $keyExtractor);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('dynamic period must be >= 1');
        $throttleRule->resolvePeriod($serverRequest);
    }
}
