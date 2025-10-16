<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class PerformanceTest extends TestCase
{
    private function handler(): \Psr\Http\Server\RequestHandlerInterface
    {
        return new class () implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new \Nyholm\Psr7\Response(200);
            }
        };
    }

    public function testEventOnSafelistPass(): void
    {
        $cache = new InMemoryCache();
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
        $config = new Config($cache, $events);
        $config->safelist('all', fn ($request): bool => true);
        $middleware = new Middleware($config);
        $events->start = microtime(true);
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(200, $response->getStatusCode());

        $this->assertInstanceOf(SafelistMatched::class, $events->eventMatched);
        $this->assertGreaterThan(0, $events->durationMicros ?? 0);
    }

    public function testEventOnThrottle(): void
    {
        $cache = new InMemoryCache();
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
        $config = new Config($cache, $events);
        $config->throttle('ip', 0, 10, fn ($request): string => '1.1.1.1');
        $middleware = new Middleware($config);
        $events->start = microtime(true);
        $response = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(429, $response->getStatusCode());

        $this->assertInstanceOf(ThrottleExceeded::class, $events->eventMatched);
        $this->assertSame('ip', $events->eventMatched->rule);
        $this->assertGreaterThan(0, $events->durationMicros ?? 0);
    }
}
