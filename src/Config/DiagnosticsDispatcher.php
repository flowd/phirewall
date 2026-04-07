<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\StoppableEventInterface;

/**
 * PSR-14 event dispatcher that observes events for diagnostics counting.
 *
 * When an inner dispatcher is provided, events are counted and then forwarded:
 *
 *   $counters = new DiagnosticsCounters();
 *   $dispatcher = new DiagnosticsDispatcher($counters, $realDispatcher);
 *   $config = new \Flowd\Phirewall\Config($cache, $dispatcher);
 *
 * Without an inner dispatcher, events are counted only (standalone mode for testing):
 *
 *   $counters = new DiagnosticsCounters();
 *   $dispatcher = new DiagnosticsDispatcher($counters);
 *   $config = new \Flowd\Phirewall\Config($cache, $dispatcher);
 */
final readonly class DiagnosticsDispatcher implements EventDispatcherInterface
{
    public function __construct(
        private DiagnosticsCounters $counters,
        private ?EventDispatcherInterface $innerDispatcher = null,
    ) {
    }

    public function dispatch(object $event): object
    {
        if ($event instanceof StoppableEventInterface && $event->isPropagationStopped()) {
            return $event;
        }

        $this->counters->observe($event);

        return $this->innerDispatcher?->dispatch($event) ?? $event;
    }

    public function counters(): DiagnosticsCounters
    {
        return $this->counters;
    }
}
