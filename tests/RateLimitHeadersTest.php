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

final class RateLimitHeadersTest extends TestCase
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

    public function testHeadersPresentWhenEnabledAndNotExceeded(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(true);
        // Limit 3 requests per 30s by IP
        $config->throttle('ip', 3, 30, fn ($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.1.1.1']);
        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());

        $limit = $response->getHeaderLine('X-RateLimit-Limit');
        $remaining = $response->getHeaderLine('X-RateLimit-Remaining');
        $reset = $response->getHeaderLine('X-RateLimit-Reset');
        $this->assertSame('3', $limit);
        $this->assertSame('2', $remaining);
        $this->assertGreaterThanOrEqual(1, (int)$reset);
    }

    public function testHeadersPresentWhenExceededAndMatchRetryAfter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(true);
        // Limit 1 per 10s by IP
        $config->throttle('ip', 1, 10, fn ($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2.2.2.2']);
        // First ok
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        // Second should be throttled
        $response = $middleware->process($request, $handler);
        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('1', $response->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('0', $response->getHeaderLine('X-RateLimit-Remaining'));
        $reset = (int)$response->getHeaderLine('X-RateLimit-Reset');
        $retry = (int)$response->getHeaderLine('Retry-After');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertSame($retry, $reset, 'Reset should match Retry-After when throttled');
    }

    public function testHeadersAbsentWhenDisabled(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(false);
        $config->throttle('ip', 10, 60, fn ($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $middleware = new Middleware($config);

        $response = $middleware->process(new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '3.3.3.3']), $this->handler());
        $this->assertSame('', $response->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('', $response->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertSame('', $response->getHeaderLine('X-RateLimit-Reset'));
    }
}
