<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class TrackTest extends TestCase
{
    public function testTrackEmitsEventsAndDoesNotAffectOutcome(): void
    {
        $cache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];
            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($cache, $events);
        $config->track(
            'login_failed',
            period: 60,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0'
        );

        $firewall = new Firewall($config);

        $request = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']))
            ->withHeader('X-Login-Failed', '1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());

        // Collect TrackHit events
        $hits = array_values(array_filter($events->events, fn($e) => $e instanceof TrackHit));
        $this->assertCount(2, $hits);
        $this->assertInstanceOf(TrackHit::class, $hits[0]);
        $this->assertSame('login_failed', $hits[0]->rule);
        $this->assertSame('1.2.3.4', $hits[0]->key);
        $this->assertSame(60, $hits[0]->period);
        $this->assertSame(1, $hits[0]->count);
        $this->assertSame(2, $hits[1]->count);
    }

    public function testTrackFilterFalseEmitsNoEvent(): void
    {
        $cache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];
            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config($cache, $events);
        $config->track(
            'any',
            period: 30,
            filter: fn($request): bool => false,
            key: fn($request): string => 'k'
        );

        $firewall = new Firewall($config);
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $hits = array_values(array_filter($events->events, fn($e) => $e instanceof TrackHit));
        $this->assertCount(0, $hits);
    }
}
