<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class Psr17ResponseFactoryTest extends TestCase
{
    private function psr17(): Psr17Factory
    {
        return new Psr17Factory();
    }

    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    // ── Psr17BlocklistedResponseFactory ─────────────────────────────────

    public function testBlocklistedFactoryReturns403WithContentType(): void
    {
        $factory = new Psr17BlocklistedResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('test-rule', 'blocklist', new ServerRequest('GET', '/'));

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
    }

    public function testBlocklistedFactoryWritesBodyWhenStreamFactoryProvided(): void
    {
        $factory = new Psr17BlocklistedResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('test-rule', 'blocklist', new ServerRequest('GET', '/'));

        $this->assertSame('Forbidden', (string) $response->getBody());
    }

    public function testBlocklistedFactoryCustomBodyText(): void
    {
        $factory = new Psr17BlocklistedResponseFactory(
            $this->psr17(),
            $this->psr17(),
            'Access Denied',
        );
        $response = $factory->create('test-rule', 'blocklist', new ServerRequest('GET', '/'));

        $this->assertSame('Access Denied', (string) $response->getBody());
    }

    public function testBlocklistedFactoryWithoutStreamFactoryOmitsBody(): void
    {
        $factory = new Psr17BlocklistedResponseFactory($this->psr17());
        $response = $factory->create('test-rule', 'blocklist', new ServerRequest('GET', '/'));

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('', (string) $response->getBody());
    }

    // ── Psr17ThrottledResponseFactory ───────────────────────────────────

    public function testThrottledFactoryReturns429WithRetryAfterAndContentType(): void
    {
        $factory = new Psr17ThrottledResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('rate-limit', 60, new ServerRequest('GET', '/'));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('60', $response->getHeaderLine('Retry-After'));
    }

    public function testThrottledFactoryWritesBodyWhenStreamFactoryProvided(): void
    {
        $factory = new Psr17ThrottledResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('rate-limit', 30, new ServerRequest('GET', '/'));

        $this->assertSame('Too Many Requests', (string) $response->getBody());
    }

    public function testThrottledFactoryCustomBodyText(): void
    {
        $factory = new Psr17ThrottledResponseFactory(
            $this->psr17(),
            $this->psr17(),
            'Slow down, please.',
        );
        $response = $factory->create('rate-limit', 10, new ServerRequest('GET', '/'));

        $this->assertSame('Slow down, please.', (string) $response->getBody());
    }

    public function testThrottledFactoryWithoutStreamFactoryOmitsBody(): void
    {
        $factory = new Psr17ThrottledResponseFactory($this->psr17());
        $response = $factory->create('rate-limit', 45, new ServerRequest('GET', '/'));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('45', $response->getHeaderLine('Retry-After'));
        $this->assertSame('', (string) $response->getBody());
    }

    public function testThrottledFactoryRetryAfterIsAtLeastOne(): void
    {
        $factory = new Psr17ThrottledResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('rate-limit', 0, new ServerRequest('GET', '/'));

        $this->assertSame('1', $response->getHeaderLine('Retry-After'));
    }

    // ── Config::usePsr17Responses ───────────────────────────────────────

    public function testUsePsr17ResponsesSetsBothFactories(): void
    {
        $config = new Config(new InMemoryCache());
        $result = $config->usePsr17Responses($this->psr17(), $this->psr17());

        $this->assertSame($config, $result, 'usePsr17Responses() should be fluent');
        $this->assertInstanceOf(Psr17BlocklistedResponseFactory::class, $config->blocklistedResponseFactory);
        $this->assertInstanceOf(Psr17ThrottledResponseFactory::class, $config->throttledResponseFactory);
    }

    public function testUsePsr17ResponsesWorksWithoutStreamFactory(): void
    {
        $config = new Config(new InMemoryCache());
        $config->usePsr17Responses($this->psr17());

        $this->assertInstanceOf(Psr17BlocklistedResponseFactory::class, $config->blocklistedResponseFactory);
        $this->assertInstanceOf(Psr17ThrottledResponseFactory::class, $config->throttledResponseFactory);
    }

    // ── Middleware integration ───────────────────────────────────────────

    public function testMiddlewareUsesBlocklistedPsr17Factory(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableResponseHeaders();
        $config->usePsr17Responses($this->psr17(), $this->psr17());

        $config->blocklists->add('all', fn(ServerRequestInterface $serverRequest): bool => true);

        $middleware = new Middleware($config, $this->psr17());
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('Forbidden', (string) $response->getBody());
        $this->assertSame('blocklist', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('all', $response->getHeaderLine('X-Phirewall-Matched'));
    }

    public function testMiddlewareUsesThrottledPsr17Factory(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableResponseHeaders();
        $config->usePsr17Responses($this->psr17(), $this->psr17());

        $config->throttles->add('ip', 0, 30, fn(ServerRequestInterface $serverRequest): string => '1.2.3.4');

        $middleware = new Middleware($config, $this->psr17());
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertSame('Too Many Requests', (string) $response->getBody());
        $this->assertSame('throttle', $response->getHeaderLine('X-Phirewall'));
        $this->assertSame('ip', $response->getHeaderLine('X-Phirewall-Matched'));
        $this->assertNotSame('', $response->getHeaderLine('Retry-After'));
    }

    public function testMiddlewarePsr17FactoryTakesPrecedenceOverFallback(): void
    {
        $config = new Config(new InMemoryCache());
        $config->usePsr17Responses($this->psr17(), $this->psr17());

        $config->blocklists->add('all', fn(ServerRequestInterface $serverRequest): bool => true);

        // Pass a separate PSR-17 factory as the fallback -- the configured one should win
        $middleware = new Middleware($config, new Psr17Factory());
        $response = $middleware->process(new ServerRequest('GET', '/test'), $this->handler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('Forbidden', (string) $response->getBody());
    }

    public function testMiddlewareFallsBackToConstructorResponseFactoryWhenNoPsr17Configured(): void
    {
        $config = new Config(new InMemoryCache());
        // No usePsr17Responses() call -- both factory properties remain null
        $config->blocklists->add('all', fn(ServerRequestInterface $serverRequest): bool => true);

        $middleware = new Middleware($config, $this->psr17());
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        // Body should be empty since the fallback only creates a bare 403
        $this->assertSame('', (string) $response->getBody());
    }

    public function testMiddlewareFallsBackToConstructorResponseFactoryForThrottle(): void
    {
        $config = new Config(new InMemoryCache());
        // No usePsr17Responses() call -- both factory properties remain null
        $config->throttles->add('ip', 0, 60, fn(ServerRequestInterface $serverRequest): string => '10.0.0.1');

        $middleware = new Middleware($config, $this->psr17());
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        $this->assertNotSame('', $response->getHeaderLine('Retry-After'));
    }

    public function testThrottledFactoryRetryAfterNegativeValueBecomesOne(): void
    {
        $factory = new Psr17ThrottledResponseFactory($this->psr17(), $this->psr17());
        $response = $factory->create('rate-limit', -5, new ServerRequest('GET', '/'));

        $this->assertSame('1', $response->getHeaderLine('Retry-After'));
    }
}
