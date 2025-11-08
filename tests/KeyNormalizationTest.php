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

final class KeyNormalizationTest extends TestCase
{
    public function testTrackKeyNormalizationHandlesWeirdCharacters(): void
    {
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };
        $config = new Config($inMemoryCache, $events);
        $config->track(
            'hits weird name',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => "/weird path\t\n<>#?"
        );

        $firewall = new Firewall($config);
        // Two requests should produce two TrackHit events with incrementing counts
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());

        $hits = array_values(array_filter($events->events, fn($e): bool => $e instanceof TrackHit));
        $this->assertCount(2, $hits);
        $this->assertSame(1, $hits[0]->count);
        $this->assertSame(2, $hits[1]->count);
        // Ensure rule name is normalized but exposed as provided
        $this->assertSame('hits weird name', $hits[0]->rule);
        // Key may be sanitized internally; we only ensure it is non-empty
        $this->assertNotSame('', $hits[0]->key);
    }

    public function testVeryLongKeyDoesNotExplodeAndCounts(): void
    {
        $veryLong = str_repeat('a', 500) . '/something';
        $inMemoryCache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };
        $config = new Config($inMemoryCache, $events);
        $config->track(
            'long',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => $veryLong
        );
        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());

        $hits = array_values(array_filter($events->events, fn($e): bool => $e instanceof TrackHit));
        $this->assertCount(2, $hits);
        $this->assertSame(1, $hits[0]->count);
        $this->assertSame(2, $hits[1]->count);
        // Internal key length/format is opaque; we only assert counting works.
    }
}
