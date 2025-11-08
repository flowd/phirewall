<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\RedisCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RedisCacheTest extends TestCase
{
    public function testCanConstructWithoutRedisServer(): void
    {
        if (!class_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed; skipping construction test.');
        }

        $client = $this->createMock(\Predis\ClientInterface::class);
        $redisCache = new RedisCache($client);
        $this->assertInstanceOf(RedisCache::class, $redisCache);
    }

    public function testIntegrationIfRedisAvailable(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            $this->markTestSkipped('Predis is not installed; skipping Redis integration test');
        }

        $url = getenv('REDIS_URL');
        if ($url === '' || $url === '0' || $url === [] || $url === false) {
            $this->markTestSkipped('REDIS_URL not set; skipping Redis integration test');
        }

        $client = new \Predis\Client($url);

        // phpstan fails to recognize that $client implements ClientInterface if predis is installed
        assert($client instanceof \Predis\ClientInterface);
        assert(method_exists($client, 'ping'));
        assert(method_exists($client, 'flushdb'));

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
        $redisCache = new RedisCache($client, 'Phirewall:test:');

        $config = new Config($redisCache);
        $config->throttle('ip', 1, 5, fn($request): string => '1.2.3.4');

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $second = $firewall->decide($serverRequest);
        $this->assertSame(OUTCOME::THROTTLED, $second->outcome);
        $retry = (int)($second->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertLessThanOrEqual(5, $retry);
    }
}
