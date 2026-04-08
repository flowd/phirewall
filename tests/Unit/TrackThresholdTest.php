<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class TrackThresholdTest extends TestCase
{
    /**
     * Without a limit, TrackHit fires on every matching request with thresholdReached=false.
     */
    public function testNoLimitFiresOnEveryMatch(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'all-requests',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        $firewall->decide($request);
        $firewall->decide($request);
        $firewall->decide($request);

        $hits = $this->trackHits($events->events);
        $this->assertCount(3, $hits);
        $this->assertSame(1, $hits[0]->count);
        $this->assertNull($hits[0]->limit, 'TrackHit should carry null limit when none configured');
        $this->assertFalse($hits[0]->thresholdReached, 'No limit means threshold is never reached');
        $this->assertSame(2, $hits[1]->count);
        $this->assertSame(3, $hits[2]->count);
    }

    /**
     * With limit=5, TrackHit always fires but thresholdReached is only true at count >= 5.
     */
    public function testThresholdReachedFlagReflectsLimit(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'login-failures',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'user-1',
            limit: 5,
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('POST', '/login');

        // Requests 1-4: below threshold, events fire with thresholdReached=false
        for ($i = 1; $i <= 4; ++$i) {
            $firewall->decide($request);
        }

        $hits = $this->trackHits($events->events);
        $this->assertCount(4, $hits, 'TrackHit fires on every request');
        foreach ($hits as $hit) {
            $this->assertFalse($hit->thresholdReached, 'Below threshold');
        }

        // Request 5: reaches threshold, thresholdReached=true
        $firewall->decide($request);

        $hits = $this->trackHits($events->events);
        $this->assertCount(5, $hits);
        $this->assertSame(5, $hits[4]->count);
        $this->assertSame('login-failures', $hits[4]->rule);
        $this->assertSame('user-1', $hits[4]->key);
        $this->assertSame(5, $hits[4]->limit);
        $this->assertTrue($hits[4]->thresholdReached);

        // Request 6: above threshold, still thresholdReached=true
        $firewall->decide($request);

        $hits = $this->trackHits($events->events);
        $this->assertCount(6, $hits);
        $this->assertSame(6, $hits[5]->count);
        $this->assertTrue($hits[5]->thresholdReached);
    }

    /**
     * Track with threshold is still passive -- it must not block traffic.
     */
    public function testTrackWithLimitDoesNotAffectOutcome(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'observed',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
            limit: 2,
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        for ($i = 0; $i < 10; ++$i) {
            $this->assertTrue($firewall->decide($request)->isPass());
        }
    }

    /**
     * Backward compatibility: calling tracks->add() without a limit parameter
     * works identically to the original behavior.
     */
    public function testBackwardCompatWithoutLimit(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'compat',
            period: 30,
            filter: fn($request): bool => $request->getHeaderLine('X-Test') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0',
        );

        $firewall = new Firewall($config);

        $request = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Test', '1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());

        $hits = $this->trackHits($events->events);
        $this->assertCount(2, $hits);
        $this->assertSame('compat', $hits[0]->rule);
        $this->assertSame('10.0.0.1', $hits[0]->key);
        $this->assertSame(30, $hits[0]->period);
        $this->assertSame(1, $hits[0]->count);
        $this->assertNull($hits[0]->limit);
        $this->assertSame(2, $hits[1]->count);
    }

    /**
     * The limit() getter returns null when no limit is configured.
     */
    public function testTrackRuleLimitGetterReturnsNullByDefault(): void
    {
        $config = $this->createConfig();
        $config->tracks->add(
            'no-limit',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
        );

        $rules = $config->tracks->rules();
        $this->assertNull($rules['no-limit']->limit());
    }

    /**
     * The limit() getter returns the configured value.
     */
    public function testTrackRuleLimitGetterReturnsConfiguredValue(): void
    {
        $config = $this->createConfig();
        $config->tracks->add(
            'with-limit',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
            limit: 10,
        );

        $rules = $config->tracks->rules();
        $this->assertSame(10, $rules['with-limit']->limit());
    }

    /**
     * Multiple track rules with different limits work independently.
     */
    public function testMultipleTrackRulesWithDifferentLimits(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'every-hit',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
        );
        $config->tracks->add(
            'threshold-3',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
            limit: 3,
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        for ($i = 1; $i <= 4; ++$i) {
            $firewall->decide($request);
        }

        $hits = $this->trackHits($events->events);
        $everyHits = array_values(array_filter($hits, static fn(TrackHit $trackHit): bool => $trackHit->rule === 'every-hit'));
        $thresholdHits = array_values(array_filter($hits, static fn(TrackHit $trackHit): bool => $trackHit->rule === 'threshold-3'));

        $this->assertCount(4, $everyHits, 'Rule without limit fires every time');
        $this->assertCount(4, $thresholdHits, 'Rule with limit always fires');

        // Below threshold: thresholdReached=false
        $this->assertFalse($thresholdHits[0]->thresholdReached);
        $this->assertFalse($thresholdHits[1]->thresholdReached);

        // At and above threshold: thresholdReached=true
        $this->assertTrue($thresholdHits[2]->thresholdReached);
        $this->assertSame(3, $thresholdHits[2]->count);
        $this->assertTrue($thresholdHits[3]->thresholdReached);
        $this->assertSame(4, $thresholdHits[3]->count);

        // Verify limit is carried on the event
        $this->assertNull($everyHits[0]->limit);
        $this->assertFalse($everyHits[0]->thresholdReached);
        $this->assertSame(3, $thresholdHits[0]->limit);
    }

    /**
     * A limit of zero is invalid and must throw.
     */
    public function testLimitZeroThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('limit must be at least 1');

        new TrackRule(
            'bad-rule',
            60,
            new ClosureRequestMatcher(fn($request): bool => true),
            new ClosureKeyExtractor(fn($request): string => 'k'),
            0,
        );
    }

    /**
     * A negative limit is invalid and must throw.
     */
    public function testNegativeLimitThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('limit must be at least 1');

        new TrackRule(
            'bad-rule',
            60,
            new ClosureRequestMatcher(fn($request): bool => true),
            new ClosureKeyExtractor(fn($request): string => 'k'),
            -5,
        );
    }

    /**
     * A limit of 1 is valid and fires immediately on the first match.
     */
    public function testLimitOfOneFiresImmediately(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->tracks->add(
            'instant',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
            limit: 1,
        );

        $firewall = new Firewall($config);
        $firewall->decide(new ServerRequest('GET', '/'));

        $hits = $this->trackHits($events->events);
        $this->assertCount(1, $hits);
        $this->assertSame(1, $hits[0]->count);
        $this->assertSame(1, $hits[0]->limit);
        $this->assertTrue($hits[0]->thresholdReached);
    }

    /**
     * The deprecated Config::track() method accepts a limit parameter.
     */
    public function testDeprecatedTrackMethodAcceptsLimit(): void
    {
        $events = $this->createCollectingDispatcher();

        $config = $this->createConfig($events);
        $config->track(
            'deprecated-with-limit',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => 'k',
            limit: 3,
        );

        $rules = $config->tracks->rules();
        $this->assertSame(3, $rules['deprecated-with-limit']->limit());

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        // First 2 requests: events fire but thresholdReached=false
        $firewall->decide($request);
        $firewall->decide($request);

        $hits = $this->trackHits($events->events);
        $this->assertCount(2, $hits);
        $this->assertFalse($hits[0]->thresholdReached);
        $this->assertFalse($hits[1]->thresholdReached);

        // Third request: thresholdReached=true
        $firewall->decide($request);
        $hits = $this->trackHits($events->events);
        $this->assertCount(3, $hits);
        $this->assertSame(3, $hits[2]->count);
        $this->assertTrue($hits[2]->thresholdReached);
    }

    /**
     * PortableConfig supports track rules with limit.
     */
    public function testPortableConfigTrackWithLimit(): void
    {
        $portable = PortableConfig::create();
        $portable->track(
            'portable-tracked',
            period: 120,
            filter: PortableConfig::filterAll(),
            key: PortableConfig::keyIp(),
            limit: 10,
        );

        $schema = $portable->toArray();
        $trackEntry = $schema['tracks'][0];
        $this->assertArrayHasKey('limit', $trackEntry, 'Limit key should be present in schema');
        $this->assertSame(10, $trackEntry['limit'] ?? null);

        // Round-trip: export -> import -> toConfig
        $restored = PortableConfig::fromArray($schema);
        $events = $this->createCollectingDispatcher();
        $config = $restored->toConfig(new InMemoryCache(), $events);

        $rules = $config->tracks->rules();
        $this->assertArrayHasKey('portable-tracked', $rules);
        $this->assertSame(10, $rules['portable-tracked']->limit());
    }

    /**
     * PortableConfig track without limit omits the key from the schema.
     */
    public function testPortableConfigTrackWithoutLimit(): void
    {
        $portable = PortableConfig::create();
        $portable->track(
            'no-limit',
            period: 60,
            filter: PortableConfig::filterAll(),
            key: PortableConfig::keyIp(),
        );

        $schema = $portable->toArray();
        $this->assertArrayNotHasKey('limit', $schema['tracks'][0]);

        $restored = PortableConfig::fromArray($schema);
        $config = $restored->toConfig(new InMemoryCache());
        $this->assertNull($config->tracks->rules()['no-limit']->limit());
    }

    private function createConfig(?EventDispatcherInterface $eventDispatcher = null): Config
    {
        return new Config(new InMemoryCache(), $eventDispatcher);
    }

    /**
     * @return EventDispatcherInterface&object{events: list<object>}
     */
    private function createCollectingDispatcher(): EventDispatcherInterface
    {
        return new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };
    }

    /**
     * @param list<object> $events
     * @return list<TrackHit>
     */
    private function trackHits(array $events): array
    {
        return array_values(array_filter($events, static fn(object $e): bool => $e instanceof TrackHit));
    }
}
