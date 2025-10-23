<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KeyPrefixTest extends TestCase
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

    public function testCustomKeyPrefixIsAppliedToCounters(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->setKeyPrefix('custom');

        // Use a track rule so we can observe a counter without blocking
        $config->track(
            'hits',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k'
        );

        $middleware = new Middleware($config);
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(200, $response->getStatusCode());

        // Build expected key via Middleware private method using reflection
        $ref = new \ReflectionClass(Middleware::class);
        $method = $ref->getMethod('trackKey');
        $method->setAccessible(true);
        /** @var string $key */
        $key = $method->invoke($middleware, 'hits', 'k');

        $this->assertSame('custom:track:hits:k', $key);
        $this->assertSame(1, $cache->get($key, 0));
    }
}
