<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\RedisCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RedisCache::class)]
final class RedisCacheTest extends TestCase
{
    public function testIncrementReturnsZeroAndTriggersWarningWhenEvalThrows(): void
    {
        if (!interface_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed.');
        }

        $client = $this->createMock(\Predis\ClientInterface::class);
        $client
            ->method('eval')
            ->willThrowException(new \RuntimeException('Connection refused'));

        $cache = new RedisCache($client);

        $capturedWarnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$capturedWarnings): bool {
            if ($errno === E_USER_WARNING) {
                $capturedWarnings[] = ['errno' => $errno, 'errstr' => $errstr];
                return true;
            }

            return false;
        });

        try {
            $result = $cache->increment('my-counter', 60);
        } finally {
            restore_error_handler();
        }

        $this->assertSame(0, $result, 'increment() must fail open and return 0 on Redis error');
        $this->assertCount(1, $capturedWarnings, 'Exactly one E_USER_WARNING should be triggered');
        $this->assertSame(E_USER_WARNING, $capturedWarnings[0]['errno']);
        $this->assertStringContainsString('RedisCache::increment()', $capturedWarnings[0]['errstr']);
        $this->assertStringContainsString('my-counter', $capturedWarnings[0]['errstr']);
        $this->assertStringContainsString('Connection refused', $capturedWarnings[0]['errstr']);
    }

    public function testIncrementFailsOpenWhenErrorHandlerThrows(): void
    {
        if (!interface_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed.');
        }

        $client = $this->createMock(\Predis\ClientInterface::class);
        $client
            ->method('eval')
            ->willThrowException(new \RuntimeException('Connection refused'));

        $cache = new RedisCache($client);

        // Simulate a framework error handler that converts warnings to exceptions
        set_error_handler(static function (int $errno, string $errstr): bool {
            throw new \ErrorException($errstr, 0, $errno);
        });

        try {
            $result = $cache->increment('my-counter', 60);
        } finally {
            restore_error_handler();
        }

        $this->assertSame(0, $result, 'increment() must fail open even when error handler throws');
    }
}
