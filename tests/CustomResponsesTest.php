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

final class CustomResponsesTest extends TestCase
{
    private function handler(): \Psr\Http\Server\RequestHandlerInterface
    {
        return new class () implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testCustomBlocklistedResponseIsUsedForBlocklistAndFail2Ban(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);

        // Block everything via blocklist
        $config->blocklist('all', fn($request): bool => true);

        // Custom blocklisted response factory
        $config->blocklistedResponse(function (string $rule, string $type, \Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface {
            // Return a JSON 451 just for testing; middleware should still add X-Phirewall headers
            $body = json_encode(['blocked' => $rule, 'type' => $type], JSON_THROW_ON_ERROR);
            return new Response(451, ['Content-Type' => 'application/json'], $body);
        });

        $middleware = new Middleware($config, new Psr17Factory());
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(451, $response->getStatusCode());
        $this->assertSame('blocklist', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('all', $response->getHeaderLine('X-Phirewall-Matched'));
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));

        // Now test fail2ban uses the same factory and attaches correct type
        $inMemoryCache->clear();
        $config = new Config($inMemoryCache);
        $config->fail2ban(
            'login',
            1,
            60,
            600,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => 'ip-1'
        );
        $config->blocklistedResponse(fn(string $rule, string $type, \Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface => new Response(499, ['X-Custom' => $type]));

        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->handler();
        // One failure to trigger ban
        $request = (new ServerRequest('POST', '/login'))->withHeader('X-Login-Failed', '1');
        $middleware->process($request, $handler);
        // Next request should be banned with custom response
        $secondResponse = $middleware->process(new ServerRequest('GET', '/'), $handler);
        $this->assertSame(499, $secondResponse->getStatusCode());
        $this->assertSame('fail2ban', $secondResponse->getHeaderLine('X-Phirewall'));
        $this->assertSame('login', $secondResponse->getHeaderLine('X-Phirewall-Matched'));
        $this->assertSame('fail2ban', $secondResponse->getHeaderLine('X-Custom'));
    }

    public function testCustomThrottledResponseIsUsedAndRetryAfterEnsured(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('ip', 0, 30, fn($request): string => '1.2.3.4');

        // Custom throttled response without Retry-After header
        $config->throttledResponse(fn(string $rule, int $retryAfter, \Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface => new Response(429, ['X-Custom' => 'yes']));

        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->handler();
        $response = $middleware->process(new ServerRequest('GET', '/'), $handler);
        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('throttle', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('ip', $response->getHeaderLine('X-Phirewall-Matched'));
        $this->assertSame('yes', $response->getHeaderLine('X-Custom'));
        $this->assertNotSame('', $response->getHeaderLine('Retry-After'), 'Retry-After header should be ensured by middleware');
    }
}
