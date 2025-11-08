<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class TrustedProxyTest extends TestCase
{
    public function testClientIpFallsBackToRemoteAddrWhenNoProxy(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.10']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'Throttle should use REMOTE_ADDR as key');
    }

    public function testClientIpUsesXffWhenRemoteTrusted(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Behind a trusted proxy 10.0.0.1 with XFF chain
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertSame('by_client', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testIgnoresXffWhenRemoteNotTrusted(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'Should still throttle by REMOTE_ADDR, ignoring XFF');
    }

    public function testMultipleProxiesReturnsFirstUntrustedLeftOfTrustedChain(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // XFF: client 198.51.100.20, proxy 203.0.113.9, trusted proxy 10.0.0.1
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '198.51.100.20, 203.0.113.9, 10.0.0.1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }
}
