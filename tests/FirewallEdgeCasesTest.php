<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallEdgeCasesTest extends TestCase
{
    public function testNullKeyFromExtractorSkipsThrottle(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->add('ip', 1, 60, fn($r): null => null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/');

        // Should pass even though limit=1, because null key means skip
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
    }

    public function testNullKeyFromExtractorSkipsFail2Ban(): void
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add('login', 1, 60, 900, fn($r): true => true, fn($r): null => null);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
    }

    public function testSafelistBypassesFail2Ban(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->add('always', fn($r): bool => true);
        $config->fail2ban->add('strict', 1, 60, 900, fn($r): true => true, fn($r): string => '127.0.0.1');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/');

        // Safelist short-circuits — fail2ban never evaluated
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }

    public function testSafelistBypassesThrottle(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->add('always', fn($r): bool => true);
        $config->throttles->add('strict', 0, 60, fn($r): string => '127.0.0.1');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }

    public function testBlocklistBeforeThrottle(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->add('all', fn($r): bool => true);
        $config->throttles->add('never-reached', 10, 60, fn($r): string => '127.0.0.1');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('blocklist', $firewallResult->headers['X-Phirewall'] ?? '');
    }

    public function testMultipleSafelistsFirstMatchWins(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->add('first', fn($r): bool => $r->getUri()->getPath() === '/health');
        $config->safelists->add('second', fn($r): true => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));

        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
        $this->assertSame('first', $firewallResult->headers['X-Phirewall-Safelist'] ?? '');
    }

    public function testNoRulesResultsInPass(): void
    {
        $config = new Config(new InMemoryCache());
        $firewall = new Firewall($config);

        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::PASS, $firewallResult->outcome);
    }

    public function testEmptyRequestNoIpNoHeaders(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->add('ip', 5, 60, fn($r) => $r->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);
        // Request with no server params → null key → skip
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());
    }

    public function testMultipleThrottlesAllEvaluated(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->add('lenient', 100, 60, fn($r): string => '127.0.0.1');
        $config->throttles->add('strict', 1, 60, fn($r): string => '127.0.0.1');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '127.0.0.1']);

        $firewall->decide($serverRequest); // passes both
        $firewallResult = $firewall->decide($serverRequest); // hits strict

        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertSame('strict', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }
}
