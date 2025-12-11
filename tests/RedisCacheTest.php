<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\RedisCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class RedisCacheTest extends TestCase
{
    public function testIncrementUsesFixedWindowAndReturnsScalar(): void
    {
        if (!class_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed; skipping Redis increment unit test.');
        }

        /** @var MockObject&\Predis\ClientInterface $client */
        $client = $this->createMock(\Predis\ClientInterface::class);
        $redisCache = new RedisCache($client, 'Phirewall:test:');

        $client
            ->expects($this->once())
            ->method('eval')
            ->with(
                $this->isType('string'),
                1,
                $this->stringStartsWith('Phirewall:test:'),
                $this->isType('string')
            )
            ->willReturn(3); // simulate INCR result

        $value = $redisCache->increment('rate:foo', 10);
        $this->assertSame(3, $value);
    }

    public function testTtlRemainingClampsNegativeToZero(): void
    {
        if (!class_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed; skipping Redis TTL unit test.');
        }

        /** @var MockObject&\Predis\ClientInterface $client */
        $client = $this->createMock(\Predis\ClientInterface::class);
        $redisCache = new RedisCache($client, 'Phirewall:test:');

        $call = 0;
        $client
            ->method('ttl')
            ->willReturnCallback(function (string $key) use (&$call): int {
                ++$call;
                return $call === 1 ? -1 : 5;
            });

        $this->assertSame(0, $redisCache->ttlRemaining('foo'));
        $this->assertSame(5, $redisCache->ttlRemaining('foo'));
    }

    public function testCanConstructWithoutRedisServer(): void
    {
        if (!class_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed; skipping construction test.');
        }

        /** @var MockObject&\Predis\ClientInterface $client */
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
        $this->assertSame(Outcome::THROTTLED, $second->outcome);
        $retry = (int)($second->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertLessThanOrEqual(5, $retry);
    }
}
