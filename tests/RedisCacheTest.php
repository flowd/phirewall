<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RedisCacheTest extends TestCase
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

    public function testCanConstructWithoutRedisServer(): void
    {
        if (!class_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed; skipping construction test.');
        }
        $client = $this->createMock(\Predis\ClientInterface::class);
        $cache = new RedisCache($client);
        $this->assertInstanceOf(RedisCache::class, $cache);
    }

    public function testIntegrationIfRedisAvailable(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            $this->markTestSkipped('Predis is not installed; skipping Redis integration test');
        }
        $url = getenv('REDIS_URL');
        if (!$url) {
            $this->markTestSkipped('REDIS_URL not set; skipping Redis integration test');
        }
        $client = new \Predis\Client($url);
        try {
            // Basic ping to ensure availability
            $pong = (string)$client->ping();
            if (stripos($pong, 'PONG') === false) {
                $this->markTestSkipped('Redis did not respond with PONG');
            }
        } catch (\Throwable) {
            $this->markTestSkipped('Redis not reachable');
        }

        $client->flushdb();
        // phpstan: Predis\Client may not be discoverable as implementing ClientInterface when predis is not installed
        // @phpstan-ignore-next-line
        $cache = new RedisCache($client, 'flowd-firewall:test:');

        $config = new Config($cache);
        $config->throttle('ip', 1, 5, fn($request): string => '1.2.3.4');
        $middleware = new Middleware($config);

        $request = new ServerRequest('GET', '/');
        $firstResponse = $middleware->process($request, $this->handler());
        $this->assertSame(200, $firstResponse->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode());
        $retry = (int)$secondResponse->getHeaderLine('Retry-After');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertLessThanOrEqual(5, $retry);
    }
}
