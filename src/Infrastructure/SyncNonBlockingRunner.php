<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

/**
 * A minimal runner that executes tasks synchronously.
 *
 * Useful for tests or environments where true async is not available.
 */
final class SyncNonBlockingRunner implements NonBlockingRunnerInterface
{
    public function run(callable $task): void
    {
        try {
            $task();
        } catch (\Throwable) {
            // Swallow to avoid affecting request lifecycle; real impl could log
        }
    }
}
