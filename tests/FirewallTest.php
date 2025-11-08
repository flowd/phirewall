<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallTest extends TestCase
{
    public function testSafelistBypassesOtherRules(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->safelist('healthcheck', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklist('block-all', function ($request): bool {
            return true; // should be bypassed by safelist
        });

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/health');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
        $this->assertSame('healthcheck', $firewallResult->headers['X-Phirewall-Safelist'] ?? '');
    }

    public function testBlocklistBlocks(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/admin');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('blocklist', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('blockedPath', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottle429AndRetryAfter(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('ip', 2, 10, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $retryAfter = (int)($firewallResult->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retryAfter);
    }

    public function testFail2BanBlocksAfterThreshold(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->fail2ban(
            'login',
            2,
            5,
            10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        // First failure
        $failedRequest = $serverRequest->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Second failure -> hits threshold and sets ban
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Now even a normal request should be banned
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('fail2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }
}
