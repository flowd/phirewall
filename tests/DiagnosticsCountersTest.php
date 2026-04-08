<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class DiagnosticsCountersTest extends TestCase
{
    public function testSafelistCounterIncrements(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->safelist('health', fn($req): bool => $req->getUri()->getPath() === '/health');
        $config->blocklist('block-all', fn(): bool => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));
        $this->assertTrue($firewallResult->isPass());

        $counters = $diagnosticsCounters->all();
        $this->assertArrayHasKey('safelisted', $counters);
        $this->assertSame(1, $counters['safelisted']['total']);
        $this->assertSame(1, $counters['safelisted']['by_rule']['health'] ?? 0);
        $this->assertArrayNotHasKey('passed', $counters);
    }

    public function testBlocklistCounterIncrements(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->blocklist('admin', fn($req): bool => $req->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertTrue($firewallResult->isBlocked());

        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['blocklisted']['total'] ?? 0);
        $this->assertSame(1, $counters['blocklisted']['by_rule']['admin'] ?? 0);
    }

    public function testThrottleExceededCounterIncrements(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->throttle('ip', 1, 10, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['throttle_exceeded']['total'] ?? 0);
        $this->assertSame(1, $counters['throttle_exceeded']['by_rule']['ip'] ?? 0);
    }

    public function testFail2BanCountersIncrement(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->fail2ban(
            'login',
            threshold: 2,
            period: 10,
            ban: 60,
            filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
            key: fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null,
        );
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']);
        $fail = $serverRequest->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($fail)->isPass()); // 1st — within threshold
        $this->assertTrue($firewall->decide($fail)->isPass()); // 2nd — reaches threshold, still allowed
        $blockedResult = $firewall->decide($fail); // 3rd — exceeds threshold, banned
        $this->assertTrue($blockedResult->isBlocked());

        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['fail2ban_banned']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_banned']['by_rule']['login'] ?? 0);

        // Now a normal request should be blocked due to ban
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['fail2ban_blocked']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_blocked']['by_rule']['login'] ?? 0);
    }

    public function testTrackHitAndPassCountersIncrement(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->track('all', period: 60, filter: fn(): bool => true, key: fn(): string => 'k');

        $firewall = new Firewall($config);

        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());
        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['track_hit']['total'] ?? 0);
        $this->assertSame(1, $counters['track_hit']['by_rule']['all'] ?? 0);
        $this->assertSame(1, $counters['passed']['total'] ?? 0);
    }

    public function testAllow2BanBannedCounterIncrements(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->allow2ban->add(
            'api',
            threshold: 2,
            period: 10,
            banSeconds: 60,
            key: fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null,
        );
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/api', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass()); // 1st — within threshold
        $this->assertTrue($firewall->decide($serverRequest)->isPass()); // 2nd — reaches threshold
        $blockedResult = $firewall->decide($serverRequest); // 3rd — exceeds threshold, banned
        $this->assertTrue($blockedResult->isBlocked());

        $counters = $diagnosticsCounters->all();
        $this->assertSame(1, $counters['allow2ban_banned']['total'] ?? 0);
        $this->assertSame(1, $counters['allow2ban_banned']['by_rule']['api'] ?? 0);
    }

    public function testWithoutDiagnosticsNothingBreaks(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklist('all', fn(): bool => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isBlocked());
    }

    public function testResetClearsAll(): void
    {
        $diagnosticsCounters = new DiagnosticsCounters();
        $config = new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnosticsCounters));
        $config->blocklist('test', fn(): bool => true);

        $firewall = new Firewall($config);
        $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertNotEmpty($diagnosticsCounters->all());
        $diagnosticsCounters->reset();
        $this->assertSame([], $diagnosticsCounters->all());
    }
}
