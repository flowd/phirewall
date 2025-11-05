<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class KeyExtractorsTest extends TestCase
{
    public function testThrottleByIpExtractor(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('ip', 1, 30, KeyExtractors::ip());
        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertTrue($firewall->decide($request)->isPass());
        $second = $firewall->decide($request);
        $this->assertSame(FirewallResult::OUTCOME_THROTTLED, $second->outcome);
        $this->assertSame('ip', $second->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testTrackByPathAndMethodExtractors(): void
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
        // Track GET on /metrics
        $config->track(
            'hits',
            60,
            filter: fn($request): bool => KeyExtractors::method()($request) === 'GET' && KeyExtractors::path()($request) === '/metrics',
            key: KeyExtractors::path()
        );
        $firewall = new Firewall($config);

        $metricsRequest = new ServerRequest('GET', '/metrics');
        $result1 = $firewall->decide($metricsRequest);
        $this->assertTrue($result1->isPass());
        // Second request to increment counter
        $firewall->decide($metricsRequest);

        // Ensure two TrackHit events were emitted with increasing counts
        $hits = array_values(array_filter($events->events, fn($e) => $e instanceof \Flowd\Phirewall\Events\TrackHit));
        $this->assertCount(2, $hits);
        $this->assertSame(1, $hits[0]->count);
        $this->assertSame(2, $hits[1]->count);
    }

    public function testHeaderAndUserAgentExtractors(): void
    {
        $userAgentExtractor = KeyExtractors::userAgent();
        $customHeaderExtractor = KeyExtractors::header('X-Custom');
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', 'UA-1')
            ->withHeader('X-Custom', 'foo');
        $this->assertSame('UA-1', $userAgentExtractor($request));
        $this->assertSame('foo', $customHeaderExtractor($request));
    }
}
