<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class EventsTest extends TestCase
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

    public function testSafelistAndBlocklistEventsAreDispatched(): void
    {
        $cache = new InMemoryCache();
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];
            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($cache, $dispatcher);
        $config->safelist('health', fn ($request) => $request->getUri()->getPath() === '/health');
        $config->blocklist('admin', fn ($request) => $request->getUri()->getPath() === '/admin');

        $middleware = new Middleware($config);

        // Safelist path triggers safelist event and passes
        $response = $middleware->process(new ServerRequest('GET', '/health'), $this->handler());
        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotEmpty($dispatcher->events);
        $found = false;
        foreach ($dispatcher->events as $event) {
            if ($event instanceof SafelistMatched) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'SafelistMatched event not dispatched');

        // Blocklist path triggers blocklist event
        $dispatcher->events = [];
        $secondResponse = $middleware->process(new ServerRequest('GET', '/admin'), $this->handler());
        $this->assertSame(403, $secondResponse->getStatusCode());
        $foundBlock = false;
        $events = $dispatcher->events;
        /** @var list<object> $events */
        $events = $events;
        foreach ($events as $event) {
            if ($event instanceof BlocklistMatched) {
                $foundBlock = true;
                break;
            }
        }
        $this->assertTrue($foundBlock, 'BlocklistMatched event not dispatched');
    }

    public function testThrottleExceededAndFail2BanBannedEventsAreDispatched(): void
    {
        $cache = new InMemoryCache();
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];
            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($cache, $dispatcher);
        $config->throttle('ip', 1, 30, function ($request): ?string {
            return $request->getServerParams()['REMOTE_ADDR'] ?? null;
        });

        $config->fail2ban(
            'login',
            2,
            10,
            60,
            filter: function ($request): bool {
                return $request->getHeaderLine('X-Login-Failed') === '1';
            },
            key: function ($request): ?string {
                return $request->getServerParams()['REMOTE_ADDR'] ?? null;
            }
        );

        $middleware = new Middleware($config);
        $handler = $this->handler();

        // Throttle: first ok, second should exceed
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']);
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $secondResponse = $middleware->process($request, $handler);
        $this->assertSame(429, $secondResponse->getStatusCode());
        $this->assertNotEmpty($dispatcher->events);
        $foundThrottle = false;
        foreach ($dispatcher->events as $event) {
            if ($event instanceof ThrottleExceeded) {
                $foundThrottle = true;
                break;
            }
        }
        $this->assertTrue($foundThrottle, 'ThrottleExceeded event not dispatched');

        // Fail2Ban: two failures trigger ban event
        $dispatcher->events = [];
        $loginRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '8.8.8.8']))
            ->withHeader('X-Login-Failed', '1');
        $this->assertSame(200, $middleware->process($loginRequest, $handler)->getStatusCode());
        $middleware->process($loginRequest, $handler);
        $foundBan = false;
        $events = $dispatcher->events;
        /** @var list<object> $events */
        $events = $events;
        foreach ($events as $event) {
            if ($event instanceof Fail2BanBanned) {
                $foundBan = true;
                break;
            }
        }
        $this->assertTrue($foundBan, 'Fail2BanBanned event not dispatched');
    }
}
