<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\SafelistMatched;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class DiagnosticsDispatcherTest extends TestCase
{
    public function testCountsAndForwardsEventsToInnerDispatcher(): void
    {
        /** @var list<object> $forwarded */
        $forwarded = [];
        $innerDispatcher = new class ($forwarded) implements EventDispatcherInterface {
            /** @param list<object> $forwarded */
            public function __construct(public array &$forwarded)
            {
            }

            public function dispatch(object $event): object
            {
                $this->forwarded[] = $event;

                return $event;
            }
        };

        $counters = new DiagnosticsCounters();
        $dispatcher = new DiagnosticsDispatcher($counters, $innerDispatcher);

        $request = new ServerRequest('GET', '/');
        $event = new SafelistMatched('health', $request);
        $returned = $dispatcher->dispatch($event);

        // Event is returned
        $this->assertSame($event, $returned);

        // Event was forwarded to inner dispatcher
        $this->assertCount(1, $forwarded);
        $this->assertSame($event, $forwarded[0]);

        // Event was counted
        $all = $counters->all();
        $this->assertSame(1, $all['safelisted']['total']);
        $this->assertSame(1, $all['safelisted']['by_rule']['health']);
    }

    public function testStandaloneModeWithoutInnerDispatcher(): void
    {
        $counters = new DiagnosticsCounters();
        $dispatcher = new DiagnosticsDispatcher($counters);

        $request = new ServerRequest('GET', '/admin');
        $event = new BlocklistMatched('admin-block', $request);
        $returned = $dispatcher->dispatch($event);

        $this->assertSame($event, $returned);

        $all = $counters->all();
        $this->assertSame(1, $all['blocklisted']['total']);
        $this->assertSame(1, $all['blocklisted']['by_rule']['admin-block']);
    }

    public function testCountersAccessor(): void
    {
        $counters = new DiagnosticsCounters();
        $dispatcher = new DiagnosticsDispatcher($counters);

        $this->assertSame($counters, $dispatcher->counters());
    }

    public function testMultipleEventsAreCounted(): void
    {
        $counters = new DiagnosticsCounters();
        $dispatcher = new DiagnosticsDispatcher($counters);

        $request = new ServerRequest('GET', '/');

        $dispatcher->dispatch(new SafelistMatched('health', $request));
        $dispatcher->dispatch(new SafelistMatched('health', $request));
        $dispatcher->dispatch(new BlocklistMatched('scanners', $request));

        $all = $counters->all();
        $this->assertSame(2, $all['safelisted']['total']);
        $this->assertSame(2, $all['safelisted']['by_rule']['health']);
        $this->assertSame(1, $all['blocklisted']['total']);
        $this->assertSame(1, $all['blocklisted']['by_rule']['scanners']);
    }
}
