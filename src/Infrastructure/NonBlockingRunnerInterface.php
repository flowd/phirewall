<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

/**
 * Executes callables in a non-blocking manner w.r.t the current request lifecycle.
 * Implementations should ensure that dispatching a task returns quickly.
 */
interface NonBlockingRunnerInterface
{
    /**
     * Schedule a task to be executed later without blocking the caller.
     * Implementations must swallow exceptions to avoid fatal errors on shutdown,
     * but should provide a way to observe/log them if desired.
     *
     * @param callable():void $task
     */
    public function run(callable $task): void;
}
