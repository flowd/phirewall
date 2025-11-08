<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class PerformanceTest extends TestCase
{
    public function testEventOnSafelistPass(): void
    {
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public ?SafelistMatched $eventMatched = null;

            public ?int $durationMicros = null;

            public float $start = 0.0;

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                if ($event instanceof SafelistMatched && $this->start > 0) {
                    $this->eventMatched = $event;
                    $this->durationMicros = (int)round((microtime(true) - $this->start) * 1_000_000);
                }

                return $event;
            }
        };
        $config = new Config($inMemoryCache, $events);
        $config->safelist('all', fn($request): bool => true);

        $firewall = new Firewall($config);
        $events->start = microtime(true);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());

        $this->assertInstanceOf(SafelistMatched::class, $events->eventMatched);
        $this->assertGreaterThan(0, $events->durationMicros ?? 0);
    }

    public function testEventOnThrottle(): void
    {
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public ?ThrottleExceeded $eventMatched = null;

            public ?int $durationMicros = null;

            public float $start = 0.0;

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                if ($event instanceof ThrottleExceeded && $this->start > 0) {
                    $this->eventMatched = $event;
                    $this->durationMicros = (int)round((microtime(true) - $this->start) * 1_000_000);
                }

                return $event;
            }
        };
        $config = new Config($inMemoryCache, $events);
        $config->throttle('ip', 0, 10, fn($request): string => '1.1.1.1');

        $firewall = new Firewall($config);
        $events->start = microtime(true);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertSame(OUTCOME::THROTTLED, $firewallResult->outcome);

        $this->assertInstanceOf(ThrottleExceeded::class, $events->eventMatched);
        $this->assertSame('ip', $events->eventMatched->rule);
        $this->assertGreaterThan(0, $events->durationMicros ?? 0);
    }
}
