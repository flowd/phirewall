<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class MultiThrottleTest extends TestCase
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

    public function testRegistersMultipleThrottleRules(): void
    {
        $config = $this->createConfig();

        $config->throttles->multi(
            'api',
            [10 => 3, 60 => 100],
            fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $rules = $config->throttles->rules();

        $this->assertArrayHasKey('api/10s', $rules);
        $this->assertArrayHasKey('api/60s', $rules);
        $this->assertCount(2, $rules);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertSame(3, $rules['api/10s']->resolveLimit($serverRequest));
        $this->assertSame(10, $rules['api/10s']->resolvePeriod($serverRequest));

        $this->assertSame(100, $rules['api/60s']->resolveLimit($serverRequest));
        $this->assertSame(60, $rules['api/60s']->resolvePeriod($serverRequest));
    }

    public function testBurstWindowBlocksFirst(): void
    {
        $config = $this->createConfig();

        $config->throttles->multi(
            'api',
            [10 => 2, 60 => 100],
            fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // First two requests should pass
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());

        // Third request should be throttled by the burst window (api/10s)
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testEmptyWindowsThrows(): void
    {
        $config = $this->createConfig();

        $this->expectException(\InvalidArgumentException::class);

        $config->throttles->multi('api', [], fn($request): string => '1');
    }

    public function testMultiThrottleDoesNotInterfereWithSingleThrottle(): void
    {
        $config = $this->createConfig();

        $config->throttles->multi(
            'api',
            [10 => 2, 60 => 100],
            fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $config->throttles->add(
            'other',
            5,
            60,
            fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // First two requests pass (within burst limit)
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());

        // Third request is throttled by multi burst window, not by 'other'
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        // Verify 'other' rule exists independently alongside multi rules
        $rules = $config->throttles->rules();
        $this->assertArrayHasKey('api/10s', $rules);
        $this->assertArrayHasKey('api/60s', $rules);
        $this->assertArrayHasKey('other', $rules);
        $this->assertCount(3, $rules);
    }

    public function testMultiThrottleRejectsZeroPeriod(): void
    {
        $config = $this->createConfig();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('period must be >= 1');

        $config->throttles->multi(
            'api',
            [0 => 10, 60 => 100],
            fn($request): string => '127.0.0.1'
        );
    }

    public function testMultiThrottleRejectsNegativeLimit(): void
    {
        $config = $this->createConfig();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('limit must be non-negative');

        $config->throttles->multi(
            'api',
            [10 => -1, 60 => 100],
            fn($request): string => '127.0.0.1'
        );
    }

    public function testMultiThrottleSubRulesHaveCorrectNames(): void
    {
        $config = $this->createConfig();

        $config->throttles->multi(
            'api',
            [1 => 3, 10 => 50, 60 => 100, 3600 => 5000],
            fn($request) => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $rules = $config->throttles->rules();
        $expectedNames = ['api/1s', 'api/10s', 'api/60s', 'api/3600s'];

        foreach ($expectedNames as $expectedName) {
            $this->assertArrayHasKey($expectedName, $rules);
            $this->assertSame($expectedName, $rules[$expectedName]->name());
        }

        $this->assertCount(4, $rules);
    }
}
