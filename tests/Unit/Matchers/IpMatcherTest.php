<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class IpMatcherTest extends TestCase
{
    // ── Exact IP matching ───────────────────────────────────────────────

    public function testExactIpv4Match(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $matchResult = $ipMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('ip_match', $matchResult->source());
        $this->assertSame('10.0.0.1', $matchResult->metadata()['ip']);
    }

    public function testExactIpv4NoMatch(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']);

        $this->assertFalse($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testExactIpv6Match(): void
    {
        $ipMatcher = new IpMatcher(['::1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::1']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    // ── CIDR matching ───────────────────────────────────────────────────

    public function testCidr24Match(): void
    {
        $ipMatcher = new IpMatcher(['192.168.1.0/24']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.50']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testCidr24NoMatch(): void
    {
        $ipMatcher = new IpMatcher(['192.168.1.0/24']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.168.2.1']);

        $this->assertFalse($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testCidr16Match(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.0/16']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.255.1']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testCidr32MatchesExactIp(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1/32']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testIpv6CidrMatch(): void
    {
        $ipMatcher = new IpMatcher(['2001:db8::/32']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2001:0db8:0000:0000:0000:0000:0000:0001']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    public function testNoIpDoesNotMatch(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertFalse($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testInvalidIpDoesNotMatch(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => 'not-an-ip']);

        $this->assertFalse($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testInvalidCidrIsIgnored(): void
    {
        $ipMatcher = new IpMatcher(['not-a-cidr/24', '10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testMultipleEntries(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.1', '192.168.0.0/16', '::1']);

        $req1 = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $req2 = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.100']);
        $req3 = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::1']);
        $req4 = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '8.8.8.8']);

        $this->assertTrue($ipMatcher->match($req1)->isMatch());
        $this->assertTrue($ipMatcher->match($req2)->isMatch());
        $this->assertTrue($ipMatcher->match($req3)->isMatch());
        $this->assertFalse($ipMatcher->match($req4)->isMatch());
    }

    // ── SafelistSection integration ─────────────────────────────────────

    public function testSafelistSectionIpWithString(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->ip('safelist-ip', '10.0.0.1');
        $config->blocklists->add('block-all', fn($r): bool => true);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }

    public function testSafelistSectionIpWithArray(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->ip('safelist-ip', ['10.0.0.0/8', '172.16.0.0/12']);
        $config->blocklists->add('block-all', fn($r): bool => true);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '172.16.5.1']);

        $this->assertSame(Outcome::SAFELISTED, $firewall->decide($serverRequest)->outcome);
    }

    public function testSafelistSectionIpCustomName(): void
    {
        $config = new Config(new InMemoryCache());
        $safelistSection = $config->safelists->ip('internal', '10.0.0.1');

        $this->assertArrayHasKey('internal', $config->safelists->rules());
        $this->assertSame($config->safelists, $safelistSection); // fluent
    }

    // ── BlocklistSection integration ────────────────────────────────────

    public function testBlocklistSectionIpBlocks(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->ip('blocklist-ip', ['1.2.3.4', '5.6.7.0/24']);

        $firewall = new Firewall($config);

        $blocked = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.100']);
        $this->assertTrue($firewall->decide($blocked)->isBlocked());

        $allowed = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertTrue($firewall->decide($allowed)->isPass());
    }

    public function testBlocklistSectionIpCustomName(): void
    {
        $config = new Config(new InMemoryCache());
        $blocklistSection = $config->blocklists->ip('bad-actors', '1.2.3.4');

        $this->assertArrayHasKey('bad-actors', $config->blocklists->rules());
        $this->assertSame($config->blocklists, $blocklistSection); // fluent
    }

}
