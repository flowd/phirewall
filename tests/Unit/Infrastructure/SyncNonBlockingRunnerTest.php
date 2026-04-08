<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use PHPUnit\Framework\TestCase;

final class SyncNonBlockingRunnerTest extends TestCase
{
    public function testRunExecutesCallableSynchronously(): void
    {
        $runner = new SyncNonBlockingRunner();
        $executed = false;

        $runner->run(static function () use (&$executed): void {
            $executed = true;
        });

        $this->assertTrue($executed, 'Callable should have been executed synchronously');
    }

    public function testRunSwallowsExceptions(): void
    {
        $runner = new SyncNonBlockingRunner();

        // Should not throw -- exception is swallowed
        $runner->run(static function (): never {
            throw new \RuntimeException('Simulated failure');
        });

        $this->addToAssertionCount(1);
    }

    public function testRunSwallowsErrors(): void
    {
        $runner = new SyncNonBlockingRunner();

        // Should not throw -- errors are also Throwable and should be swallowed
        $runner->run(static function (): never {
            throw new \Error('Simulated fatal error');
        });

        $this->addToAssertionCount(1);
    }
}
