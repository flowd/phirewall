<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\RedisCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RedisCache::class)]
final class RedisCacheTest extends TestCase
{
    public function testIncrementRethrowsAndTriggersWarningWhenEvalThrows(): void
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

        $caught = null;

        try {
            $cache->increment('my-counter', 60);
        } catch (\Throwable $throwable) {
            $caught = $throwable;
        } finally {
            restore_error_handler();
        }

        $this->assertInstanceOf(\RuntimeException::class, $caught, 'increment() must re-throw the underlying Redis error');
        $this->assertSame('Connection refused', $caught->getMessage());

        $this->assertCount(1, $capturedWarnings, 'Exactly one E_USER_WARNING should be emitted before the re-throw');
        $this->assertSame(E_USER_WARNING, $capturedWarnings[0]['errno']);
        $this->assertStringContainsString('RedisCache::increment()', $capturedWarnings[0]['errstr']);
        $this->assertStringContainsString('my-counter', $capturedWarnings[0]['errstr']);
        $this->assertStringContainsString('Connection refused', $capturedWarnings[0]['errstr']);
    }

    public function testIncrementRethrowsEvenWhenErrorHandlerRejectsTheWarning(): void
    {
        if (!interface_exists(\Predis\ClientInterface::class)) {
            $this->markTestSkipped('Predis is not installed.');
        }

        $client = $this->createMock(\Predis\ClientInterface::class);
        $client
            ->method('eval')
            ->willThrowException(new \RuntimeException('Connection refused'));

        $cache = new RedisCache($client);

        // Simulate a framework error handler that converts warnings to exceptions.
        // The inner try/catch around trigger_error() in increment() must
        // swallow that upgrade so the original Redis exception still surfaces.
        set_error_handler(static function (int $errno, string $errstr): bool {
            throw new \ErrorException($errstr, 0, $errno);
        });

        $caught = null;

        try {
            $cache->increment('my-counter', 60);
        } catch (\Throwable $throwable) {
            $caught = $throwable;
        } finally {
            restore_error_handler();
        }

        $this->assertInstanceOf(\RuntimeException::class, $caught, 'increment() must surface the underlying Redis error even if the error handler is hostile');
        $this->assertSame('Connection refused', $caught->getMessage());
    }
}
