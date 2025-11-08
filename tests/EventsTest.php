<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class EventsTest extends TestCase
{
    public function testSafelistAndBlocklistEventsAreDispatched(): void
    {
        $inMemoryCache = new InMemoryCache();
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($inMemoryCache, $dispatcher);
        $config->safelist('health', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklist('admin', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);

        // Safelist path triggers safelist event and passes
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));
        $this->assertTrue($firewallResult->isPass());
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
        $second = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $second->outcome);
        $foundBlock = false;
        /** @var list<object> $events */
        $events = $dispatcher->events;
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
        $inMemoryCache = new InMemoryCache();
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($inMemoryCache, $dispatcher);
        $config->throttle('ip', 1, 30, fn($request): ?string => $request->getServerParams()['REMOTE_ADDR'] ?? null);

        $config->fail2ban(
            'login',
            2,
            10,
            60,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): ?string => $request->getServerParams()['REMOTE_ADDR'] ?? null
        );

        $firewall = new Firewall($config);

        // Throttle: first ok, second should exceed
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']);
        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(OUTCOME::THROTTLED, $firewallResult->outcome);
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
        $serverRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '8.8.8.8']))
            ->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewall->decide($serverRequest);
        $foundBan = false;
        /** @var list<object> $events */
        $events = $dispatcher->events;
        foreach ($events as $event) {
            if ($event instanceof Fail2BanBanned) {
                $foundBan = true;
                break;
            }
        }

        $this->assertTrue($foundBan, 'Fail2BanBanned event not dispatched');
    }
}
