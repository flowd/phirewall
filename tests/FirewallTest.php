<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallTest extends TestCase
{
    public function testSafelistBypassesOtherRules(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->safelist('healthcheck', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklist('block-all', function ($request): bool {
            return true; // should be bypassed by safelist
        });

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/health');
        $result = $firewall->decide($request);
        $this->assertTrue($result->isPass());
        $this->assertSame(FirewallResult::OUTCOME_SAFELISTED, $result->outcome);
        $this->assertSame('healthcheck', $result->headers['X-Phirewall-Safelist'] ?? '');
    }

    public function testBlocklistBlocks(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/admin');
        $result = $firewall->decide($request);
        $this->assertTrue($result->isBlocked());
        $this->assertSame(FirewallResult::OUTCOME_BLOCKED, $result->outcome);
        $this->assertSame('blocklist', $result->headers['X-Phirewall'] ?? '');
        $this->assertSame('blockedPath', $result->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottle429AndRetryAfter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('ip', 2, 10, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');
        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());
        $third = $firewall->decide($request);
        $this->assertSame(FirewallResult::OUTCOME_THROTTLED, $third->outcome);
        $retryAfter = (int)($third->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retryAfter);
    }

    public function testFail2BanBlocksAfterThreshold(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban(
            'login',
            2,
            5,
            10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );
        $firewall = new Firewall($config);

        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        // First failure
        $failedRequest = $request->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Second failure -> hits threshold and sets ban
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Now even a normal request should be banned
        $result = $firewall->decide($request);
        $this->assertTrue($result->isBlocked());
        $this->assertSame('fail2ban', $result->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $result->headers['X-Phirewall-Matched'] ?? '');
    }
}
