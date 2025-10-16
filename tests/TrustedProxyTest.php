<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class TrustedProxyTest extends TestCase
{
    private function handler(): \Psr\Http\Server\RequestHandlerInterface
    {
        return new class () implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new \Nyholm\Psr7\Response(200);
            }
        };
    }

    public function testClientIpFallsBackToRemoteAddrWhenNoProxy(): void
    {
        $resolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($resolver));
        $middleware = new Middleware($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.10']);
        $this->assertSame(200, $middleware->process($request, $this->handler())->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode(), 'Throttle should use REMOTE_ADDR as key');
    }

    public function testClientIpUsesXffWhenRemoteTrusted(): void
    {
        $resolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($resolver));
        $middleware = new Middleware($config);

        // Behind a trusted proxy 10.0.0.1 with XFF chain
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1');

        $this->assertSame(200, $middleware->process($request, $this->handler())->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode());
        $this->assertSame('by_client', $secondResponse->getHeaderLine('X-Flowd-Firewall-Matched'));
    }

    public function testIgnoresXffWhenRemoteNotTrusted(): void
    {
        $resolver = new TrustedProxyResolver(['127.0.0.1']);
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($resolver));
        $middleware = new Middleware($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9');

        $this->assertSame(200, $middleware->process($request, $this->handler())->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode(), 'Should still throttle by REMOTE_ADDR, ignoring XFF');
    }

    public function testMultipleProxiesReturnsFirstUntrustedLeftOfTrustedChain(): void
    {
        $resolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('by_client', 1, 30, KeyExtractors::clientIp($resolver));
        $middleware = new Middleware($config);

        // XFF: client 198.51.100.20, proxy 203.0.113.9, trusted proxy 10.0.0.1
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '198.51.100.20, 203.0.113.9, 10.0.0.1');

        $this->assertSame(200, $middleware->process($request, $this->handler())->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode());
    }
}
