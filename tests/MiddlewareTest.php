<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class MiddlewareTest extends TestCase
{
    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testSafelistBypassesOtherRules(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->safelist('healthcheck', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklist('block-all', function ($request): bool {
            return true; // should be bypassed by safelist
        });

        $middleware = new Middleware($config);
        $request = new ServerRequest('GET', '/health');
        $response = $middleware->process($request, $this->handler());
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('healthcheck', $response->getHeaderLine('X-Phirewall-Safelist'));
    }

    public function testBlocklistBlocks(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $middleware = new Middleware($config);
        $request = new ServerRequest('GET', '/admin');
        $response = $middleware->process($request, $this->handler());
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('blocklist', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('blockedPath', $response->getHeaderLine('X-Phirewall-Matched'));
    }

    public function testThrottle429AndRetryAfter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('ip', 2, 10, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $thirdResponse = $middleware->process($request, $handler);
        $this->assertSame(429, $thirdResponse->getStatusCode());
        $retryAfter = (int)$thirdResponse->getHeaderLine('Retry-After');
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
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        // First failure
        $failedRequest = $request->withHeader('X-Login-Failed', '1');
        $this->assertSame(200, $middleware->process($failedRequest, $handler)->getStatusCode());
        // Second failure -> hits threshold and sets ban
        $this->assertSame(200, $middleware->process($failedRequest, $handler)->getStatusCode());
        // Now even a normal request should be banned
        $response = $middleware->process($request, $handler);
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('fail2ban', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('login', $response->getHeaderLine('X-Phirewall-Matched'));
    }
}
