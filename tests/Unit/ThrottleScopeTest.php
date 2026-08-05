<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class ThrottleScopeTest extends TestCase
{
    private function createConfig(): Config
    {
        $fakeClock = new FakeClock(1_200_000_000.0);
        $inMemoryCache = new InMemoryCache($fakeClock);

        return new Config($inMemoryCache, clock: $fakeClock);
    }

    private function request(string $path, string $remoteAddress): ServerRequestInterface
    {
        return new ServerRequest('GET', $path, [], null, '1.1', ['REMOTE_ADDR' => $remoteAddress]);
    }

    public function testScopeClosureIsWrappedAsRequestMatcher(): void
    {
        $config = $this->createConfig();
        $config->throttles->add('search', 10, 60, scope: fn(ServerRequestInterface $serverRequest): bool => true);

        $scope = $config->throttles->rules()['search']->scope();
        $this->assertInstanceOf(ClosureRequestMatcher::class, $scope);
    }

    public function testScopedThrottleOnlyCountsMatchingRequests(): void
    {
        $config = $this->createConfig();
        $config->throttles->add(
            'search',
            limit: 1,
            period: 60,
            scope: fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/search'
        );

        $firewall = new Firewall($config);

        // Out-of-scope requests pass unlimited and are never counted.
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());

        // In-scope requests count against the limit.
        $this->assertTrue($firewall->decide($this->request('/search', '1.2.3.4'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('/search', '1.2.3.4'))->outcome);
    }

    public function testScopedKeylessThrottleKeysOnConfigIpResolver(): void
    {
        $config = $this->createConfig();
        $config->setIpResolver((new TrustedProxyResolver(['10.0.0.0/8']))->resolve(...));

        $config->throttles->add(
            'search',
            limit: 1,
            period: 60,
            scope: fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/search'
        );

        $firewall = new Firewall($config);

        // Both clients arrive through the same proxy peer; the resolver keys
        // them by their forwarded client IP, so their counters are independent.
        $clientA = $this->request('/search', '10.0.0.1')->withHeader('X-Forwarded-For', '203.0.113.7');
        $clientB = $this->request('/search', '10.0.0.1')->withHeader('X-Forwarded-For', '198.51.100.9');

        $this->assertTrue($firewall->decide($clientA)->isPass());
        $this->assertTrue($firewall->decide($clientB)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($clientA)->outcome);
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($clientB)->outcome);
    }

    public function testScopeCombinesWithExplicitKey(): void
    {
        $config = $this->createConfig();
        $config->throttles->add(
            'api',
            limit: 1,
            period: 60,
            key: fn(ServerRequestInterface $serverRequest): ?string => in_array($serverRequest->getHeaderLine('X-Api-Key'), ['', '0'], true) ? null : $serverRequest->getHeaderLine('X-Api-Key'),
            scope: fn(ServerRequestInterface $serverRequest): bool => str_starts_with($serverRequest->getUri()->getPath(), '/api/')
        );

        $firewall = new Firewall($config);
        $inScope = $this->request('/api/items', '1.2.3.4')->withHeader('X-Api-Key', 'token-1');

        $this->assertTrue($firewall->decide($inScope)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($inScope)->outcome);

        // In scope but with a null key: skipped, never throttled.
        $noKey = $this->request('/api/items', '1.2.3.4');
        $this->assertTrue($firewall->decide($noKey)->isPass());
        $this->assertTrue($firewall->decide($noKey)->isPass());
        $this->assertTrue($firewall->decide($noKey)->isPass());
    }

    public function testSlidingThrottleSupportsScope(): void
    {
        $config = $this->createConfig();
        $config->throttles->sliding(
            'search',
            limit: 1,
            period: 60,
            scope: fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/search'
        );

        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());

        $this->assertTrue($firewall->decide($this->request('/search', '1.2.3.4'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('/search', '1.2.3.4'))->outcome);
    }

    public function testMultiThrottlePassesScopeToAllWindows(): void
    {
        $config = $this->createConfig();
        $config->throttles->multi(
            'api',
            [1 => 1, 60 => 2],
            scope: fn(ServerRequestInterface $serverRequest): bool => str_starts_with($serverRequest->getUri()->getPath(), '/api/')
        );

        foreach (['api:1s', 'api:60s'] as $ruleName) {
            $scope = $config->throttles->rules()[$ruleName]->scope();
            $this->assertInstanceOf(ClosureRequestMatcher::class, $scope, $ruleName);
        }

        $firewall = new Firewall($config);

        // Out of scope: neither window counts.
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());
        $this->assertTrue($firewall->decide($this->request('/', '1.2.3.4'))->isPass());

        // In scope: the burst window (1 req/s) throttles the second request.
        $this->assertTrue($firewall->decide($this->request('/api/items', '1.2.3.4'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('/api/items', '1.2.3.4'))->outcome);
    }
}
