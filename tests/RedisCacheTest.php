<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\FirewallResult;
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
        $cache = new RedisCache($client, 'Phirewall:test:');

        $config = new Config($cache);
        $config->throttle('ip', 1, 5, fn($request): string => '1.2.3.4');
        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/');
        $first = $firewall->decide($request);
        $this->assertTrue($first->isPass());
        $second = $firewall->decide($request);
        $this->assertSame(FirewallResult::OUTCOME_THROTTLED, $second->outcome);
        $retry = (int)($second->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertLessThanOrEqual(5, $retry);
    }
}
