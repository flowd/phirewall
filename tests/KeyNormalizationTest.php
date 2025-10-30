<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KeyNormalizationTest extends TestCase
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

    public function testTrackKeyIsNormalizedAndSafe(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->track(
            'hits weird name',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => "/weird path\t\n<>#?"
        );

        $middleware = new Middleware($config);
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(200, $response->getStatusCode());

        $ref = new \ReflectionClass(Middleware::class);
        $method = $ref->getMethod('trackKey');
        $method->setAccessible(true);
        /** @var string $key */
        $key = $method->invoke($middleware, 'hits weird name', "/weird path\t\n<>#?");

        // Only allowed characters should be present
        $this->assertSame(1, preg_match('/^[A-Za-z0-9._:-]+$/', $key), 'Key contains disallowed characters');
        // Starts with default prefix
        $this->assertStringStartsWith('Phirewall:track:', $key);
        // Counter present
        $this->assertSame(1, $cache->get($key, 0));
    }

    public function testVeryLongKeyIsCappedWithHashAndCounts(): void
    {
        $veryLong = str_repeat('a', 500) . '/something';
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->track(
            'long',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request) => $veryLong
        );
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $middleware->process(new ServerRequest('GET', '/'), $handler);
        $middleware->process(new ServerRequest('GET', '/'), $handler);

        $ref = new \ReflectionClass(Middleware::class);
        $method = $ref->getMethod('trackKey');
        $method->setAccessible(true);
        /** @var string $key */
        $key = $method->invoke($middleware, 'long', $veryLong);

        // Enforced size bound
        $this->assertLessThanOrEqual(300, strlen($key));
        // Only allowed characters should be present
        $this->assertSame(1, preg_match('/^[A-Za-z0-9._:-]+$/', $key));
        // Counter incremented
        $this->assertSame(2, $cache->get($key, 0));
    }
}
