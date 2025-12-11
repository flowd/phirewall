<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class PerformanceTest extends TestCase
{
    public function testPerformanceMeasuredOnSafelistPass(): void
    {
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public ?PerformanceMeasured $perfEvent = null;

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                if ($event instanceof PerformanceMeasured) {
                    $this->perfEvent = $event;
                }

                return $event;
            }
        };

        $config = new Config($inMemoryCache, $events);
        $config->safelist('all', fn($request): bool => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);

        $this->assertInstanceOf(PerformanceMeasured::class, $events->perfEvent);
        $this->assertSame('safelisted', $events->perfEvent->decisionPath);
        $this->assertSame('all', $events->perfEvent->ruleName);
        $this->assertGreaterThan(0, $events->perfEvent->durationMicros);
    }

    public function testPerformanceMeasuredOnThrottle(): void
    {
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public ?PerformanceMeasured $perfEvent = null;

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                if ($event instanceof PerformanceMeasured) {
                    $this->perfEvent = $event;
                }

                return $event;
            }
        };

        $config = new Config($inMemoryCache, $events);
        $config->throttle('ip', 0, 10, fn($request): string => '1.1.1.1');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        $this->assertInstanceOf(PerformanceMeasured::class, $events->perfEvent);
        $this->assertSame('throttled', $events->perfEvent->decisionPath);
        $this->assertSame('ip', $events->perfEvent->ruleName);
        $this->assertGreaterThan(0, $events->perfEvent->durationMicros);
    }
}
