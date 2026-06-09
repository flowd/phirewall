<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

/**
 * A minimal runner that executes tasks synchronously.
 *
 * Despite the interface name, this implementation runs the task inline on the request thread, so a
 * listener wired through it (e.g. the infrastructure ban writer) adds its cost to request latency.
 * Useful for tests or environments where true async is not available; under sustained attack provide
 * a genuinely deferred runner so ban-writes do not run inline per request.
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
