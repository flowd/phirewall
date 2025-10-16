<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class DiagnosticsCountersTest extends TestCase
{
    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testSafelistCounterIncrements(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelist('health', fn ($req): bool => $req->getUri()->getPath() === '/health');
        $config->blocklist('block-all', fn (): bool => true); // should be bypassed

        $middleware = new Middleware($config);
        $response = $middleware->process(new ServerRequest('GET', '/health'), $this->handler());
        $this->assertSame(200, $response->getStatusCode());

        $counters = $config->getDiagnosticsCounters();
        $this->assertArrayHasKey('safelisted', $counters);
        $this->assertSame(1, $counters['safelisted']['total']);
        $this->assertSame(1, $counters['safelisted']['by_rule']['health'] ?? 0);
        // safelist path short-circuits, so 'passed' is not incremented here
        $this->assertArrayNotHasKey('passed', $counters);
    }

    public function testBlocklistCounterIncrements(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklist('admin', fn ($req): bool => $req->getUri()->getPath() === '/admin');
        $middleware = new Middleware($config);

        $response = $middleware->process(new ServerRequest('GET', '/admin'), $this->handler());
        $this->assertSame(403, $response->getStatusCode());

        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(1, $counters['blocklisted']['total'] ?? 0);
        $this->assertSame(1, $counters['blocklisted']['by_rule']['admin'] ?? 0);
    }

    public function testThrottleExceededCounterIncrements(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttle('ip', 1, 10, fn ($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $resp2 = $middleware->process($request, $handler);
        $this->assertSame(429, $resp2->getStatusCode());

        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(1, $counters['throttle_exceeded']['total'] ?? 0);
        $this->assertSame(1, $counters['throttle_exceeded']['by_rule']['ip'] ?? 0);
    }

    public function testFail2BanCountersIncrement(): void
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban(
            'login',
            threshold: 2,
            period: 10,
            ban: 60,
            filter: fn ($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
            key: fn ($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null,
        );
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $r = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']);
        $fail = $r->withHeader('X-Login-Failed', '1');
        // two failures to trigger ban
        $this->assertSame(200, $middleware->process($fail, $handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($fail, $handler)->getStatusCode());

        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(2, $counters['fail2ban_fail_hit']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_banned']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_banned']['by_rule']['login'] ?? 0);

        // Now a normal request should be blocked due to ban
        $blocked = $middleware->process($r, $handler);
        $this->assertSame(403, $blocked->getStatusCode());
        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(1, $counters['fail2ban_blocked']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_blocked']['by_rule']['login'] ?? 0);
    }

    public function testTrackHitAndPassCountersIncrement(): void
    {
        $config = new Config(new InMemoryCache());
        $config->track('all', period: 60, filter: fn (): bool => true, key: fn (): string => 'k');
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $resp = $middleware->process(new ServerRequest('GET', '/'), $handler);
        $this->assertSame(200, $resp->getStatusCode());
        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(1, $counters['track_hit']['total'] ?? 0);
        $this->assertSame(1, $counters['track_hit']['by_rule']['all'] ?? 0);
        $this->assertSame(1, $counters['passed']['total'] ?? 0);
    }
}
