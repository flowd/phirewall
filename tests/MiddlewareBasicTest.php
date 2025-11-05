<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class MiddlewareBasicTest extends TestCase
{
    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new Response(200, ['X-Handler' => 'ok']);
            }
        };
    }

    public function testBlocklistUsesResponseFactoryAndAppliesHeaders(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $middleware = new Middleware($config, new Psr17Factory());
        $response = $middleware->process(new ServerRequest('GET', '/admin'), $this->handler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('blocklist', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('blockedPath', $response->getHeaderLine('X-Phirewall-Matched'));
    }

    public function testThrottleUsesResponseFactoryAndEnsuresRetryAfter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(true);
        $config->throttle('ip', 1, 10, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->handler();

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
        // First request passes through and should carry ratelimit headers on the handler response
        $first = $middleware->process($request, $handler);
        $this->assertSame(200, $first->getStatusCode());
        $this->assertSame('ok', $first->getHeaderLine('X-Handler'));
        $this->assertSame('1', $first->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('0', $first->getHeaderLine('X-RateLimit-Remaining'));

        // Second request should be throttled and have Retry-After from middleware
        $second = $middleware->process($request, $handler);
        $this->assertSame(429, $second->getStatusCode());
        $this->assertSame('text/plain', $second->getHeaderLine('Content-Type'));
        $this->assertSame('throttle', $second->getHeaderLine('X-Phirewall'));
        $this->assertSame('ip', $second->getHeaderLine('X-Phirewall-Matched'));
        $this->assertNotSame('', $second->getHeaderLine('Retry-After'));
        // Reset should match Retry-After on throttled responses
        $this->assertSame($second->getHeaderLine('Retry-After'), $second->getHeaderLine('X-RateLimit-Reset'));
    }

    public function testSafelistHeadersAreAppliedToHandlerResponse(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->safelist('health', fn($req): bool => $req->getUri()->getPath() === '/health');

        $middleware = new Middleware($config, new Psr17Factory());
        $response = $middleware->process(new ServerRequest('GET', '/health'), $this->handler());

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok', $response->getHeaderLine('X-Handler'));
        $this->assertSame('health', $response->getHeaderLine('X-Phirewall-Safelist'));
    }
}
