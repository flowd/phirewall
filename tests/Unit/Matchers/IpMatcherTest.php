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
use Psr\Http\Message\ServerRequestInterface;

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

    public function testIpv4RuleMatchesIpv4MappedIpv6Peer(): void
    {
        // Dual-stack hosts present an IPv4 client as ::ffff:1.2.3.4 when the
        // PHP-FPM pool listens on an AF_INET6 socket. A rule written in IPv4
        // notation should match both presentations.
        $ipMatcher = new IpMatcher(['1.2.3.4']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:1.2.3.4']);

        $matchResult = $ipMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('::ffff:1.2.3.4', $matchResult->metadata()['ip']);
    }

    public function testIpv4MappedRuleEntryMatchesPlainIpv4Peer(): void
    {
        // The reverse of testIpv4RuleMatchesIpv4MappedIpv6Peer: a rule written
        // in IPv4-mapped IPv6 notation must match a plain-IPv4 peer. The stored
        // key is canonicalized so both presentations collapse to the same key.
        $ipMatcher = new IpMatcher(['::ffff:1.2.3.4']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testIpv4MappedRuleEntryMatchesIpv4MappedPeer(): void
    {
        $ipMatcher = new IpMatcher(['::ffff:1.2.3.4']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:1.2.3.4']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testIpv4CidrMatchesIpv4MappedIpv6Peer(): void
    {
        $ipMatcher = new IpMatcher(['10.0.0.0/24']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:10.0.0.50']);

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

    // ── IP resolver late binding ────────────────────────────────────────

    public function testMatchUsesRemoteAddrByDefaultWhenStandalone(): void
    {
        // No explicit resolver: standalone match() falls back to REMOTE_ADDR.
        $ipMatcher = new IpMatcher(['10.0.0.1']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertTrue($ipMatcher->match($serverRequest)->isMatch());
    }

    public function testMatchWithResolverUsesDefaultWhenNoExplicitResolverSet(): void
    {
        // No explicit resolver: the supplied default resolver decides the client IP.
        $ipMatcher = new IpMatcher(['203.0.113.7']);
        $serverRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Real-IP', '203.0.113.7');

        $this->assertTrue($ipMatcher->matchWithResolver($serverRequest, $this->headerResolver('X-Real-IP'))->isMatch());
    }

    public function testExplicitResolverWinsOverSuppliedDefault(): void
    {
        // An explicit resolver captured at construction is never overridden by the default.
        $ipMatcher = new IpMatcher(['203.0.113.7'], $this->headerResolver('X-Trusted-IP'));
        $serverRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Trusted-IP', '203.0.113.7')
            ->withHeader('X-Real-IP', '198.51.100.9');

        // Matches on the explicit (X-Trusted-IP) resolver, not the default (X-Real-IP).
        $this->assertTrue($ipMatcher->matchWithResolver($serverRequest, $this->headerResolver('X-Real-IP'))->isMatch());
    }

    public function testMatchWithResolverDoesNotMatchWhenResolverYieldsNull(): void
    {
        // No explicit resolver and the default resolver cannot read a client IP
        // (header absent) -> no match, regardless of the listed entries.
        $ipMatcher = new IpMatcher(['203.0.113.7']);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']);

        $this->assertFalse($ipMatcher->matchWithResolver($serverRequest, $this->headerResolver('X-Real-IP'))->isMatch());
    }

    /**
     * A resolver that reads the client IP from the named header (null when absent).
     *
     * @return \Closure(ServerRequestInterface): ?string
     */
    private function headerResolver(string $header): \Closure
    {
        return static function (ServerRequestInterface $serverRequest) use ($header): ?string {
            $value = $serverRequest->getHeaderLine($header);
            return $value === '' ? null : $value;
        };
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

    // ── Late binding through the evaluating Config ──────────────────────

    public function testSafelistIpRuleLateBindsToConfigResolver(): void
    {
        // The safelist ip() rule has no explicit resolver; the evaluator supplies
        // the Config's resolver, so the trusted IP arriving via X-Real-IP (behind a
        // proxy) is safelisted even though REMOTE_ADDR is something else.
        $config = new Config(new InMemoryCache());
        $config->setIpResolver($this->headerResolver('X-Real-IP'));

        $config->safelists->ip('trusted', '203.0.113.7');
        $config->blocklists->add('block-all', static fn($request): bool => true);

        $firewall = new Firewall($config);

        $trusted = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $this->assertSame(Outcome::SAFELISTED, $firewall->decide($trusted)->outcome);

        // A different forwarded client is not safelisted and falls through to block-all.
        $other = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '198.51.100.9');
        $this->assertTrue($firewall->decide($other)->isBlocked());
    }

    public function testIpRuleAddedBeforeResolverStillUsesItPerRequest(): void
    {
        // Ordering independence on a single Config: the ip() rule is added BEFORE
        // the resolver is set, yet late-binding picks up the resolver at request time.
        $config = new Config(new InMemoryCache());
        $config->blocklists->ip('bad', '203.0.113.7');     // added first, no explicit resolver
        $config->setIpResolver($this->headerResolver('X-Real-IP')); // set afterwards

        $firewall = new Firewall($config);

        // Banned IP arrives via the resolver's header -> blocked.
        $viaHeader = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $this->assertTrue($firewall->decide($viaHeader)->isBlocked());

        // The same address only in REMOTE_ADDR is ignored, because the rule now reads
        // the configured resolver (X-Real-IP), not REMOTE_ADDR.
        $viaRemoteAddr = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']);
        $this->assertTrue($firewall->decide($viaRemoteAddr)->isPass());
    }

}
