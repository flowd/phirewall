<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TrustedProxyTest extends TestCase
{
    public function testClientIpFallsBackToRemoteAddrWhenNoProxy(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.10']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'Throttle should use REMOTE_ADDR as key');
    }

    public function testClientIpUsesXffWhenRemoteTrusted(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1', '10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableResponseHeaders();

        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Behind a trusted proxy 10.0.0.1 with XFF chain
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertSame('by_client', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testIgnoresXffWhenRemoteNotTrusted(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['127.0.0.1']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.9');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'Should still throttle by REMOTE_ADDR, ignoring XFF');
    }

    public function testMultipleProxiesReturnsFirstUntrustedLeftOfTrustedChain(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // XFF: client 198.51.100.20, proxy 203.0.113.9, trusted proxy 10.0.0.1
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '198.51.100.20, 203.0.113.9, 10.0.0.1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testIpv6CidrTrustedProxyResolvesClientIp(): void
    {
        // 2001:db8::/32 is trusted, direct peer is inside that range
        $trustedProxyResolver = new TrustedProxyResolver(['2001:db8::/32']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2001:db8::1']);
        $request = $request->withHeader('X-Forwarded-For', '2001:db8::1234, 2001:db8::1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testAllowedHeadersRestrictsWhichHeadersAreUsed(): void
    {
        // Only trust Forwarded, ignore X-Forwarded-For
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $request = $request
            ->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1')
            ->withHeader('Forwarded', 'for="203.0.113.9"; proto=http; by="10.0.0.1"');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testDefaultAllowedHeadersIgnoresForwarded(): void
    {
        // Pins the new default: $allowedHeaders defaults to ['X-Forwarded-For']
        // only, so an RFC 7239 `Forwarded` header is silently ignored unless
        // the integrator opts in by listing it. Two requests with different
        // `for=` values but identical XFF chains must share the throttle
        // bucket — proving the resolver did not consult Forwarded at all.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1')
            ->withHeader('Forwarded', 'for="198.51.100.1"');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '203.0.113.9, 10.0.0.1')
            ->withHeader('Forwarded', 'for="198.51.100.99"');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testTrustedProxyMatchesExpandedIpv6FormInRemoteAddr(): void
    {
        // Operator wrote the compressed IPv6 form in trustedProxies, but the
        // server peer arrives in the expanded form. inet_pton canonicalises
        // both to the same 16-byte binary, so the trust check should match.
        $trustedProxyResolver = new TrustedProxyResolver(['2001:db8::1']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2001:0db8:0000:0000:0000:0000:0000:0001']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.7, 2001:0db8::1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome, 'Expanded-form proxy must be recognised as trusted, otherwise the throttle would key on the proxy address');
    }

    public function testTrustedProxyMatchesIpv4MappedIpv6PeerAgainstIpv4Rule(): void
    {
        // Operator wrote IPv4 in trustedProxies; PHP-FPM on a dual-stack listener
        // presents the same host as ::ffff:10.0.0.1. The trust check must
        // recognise both forms as the same host.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.1']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:10.0.0.1']);
        $request = $request->withHeader('X-Forwarded-For', '203.0.113.7, ::ffff:10.0.0.1');

        $this->assertTrue($firewall->decide($request)->isPass());
        $firewallResult = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testForwardedHeaderWithBracketedIpv6AndPortIsResolvedAsClientIp(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Two requests behind different trusted proxies but the same bracketed
        // IPv6+port client. If the form is parsed correctly, both share the
        // throttle bucket and the second is throttled; if not, the resolver
        // falls back to REMOTE_ADDR and the two requests get separate keys.
        $firstRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', 'for="[2001:db8::1]:443"; by="10.0.0.1"');
        $secondRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', 'for="[2001:db8::1]:443"; by="10.0.0.2"');

        $this->assertTrue($firewall->decide($firstRequest)->isPass());
        $firewallResult = $firewall->decide($secondRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testXffHeaderWithBracketedIpv6AndPortIsResolvedAsClientIp(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Forwarded-For']);
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $firstRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '[2001:db8::1]:443, 10.0.0.1');
        $secondRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('X-Forwarded-For', '[2001:db8::1]:443, 10.0.0.2');

        $this->assertTrue($firewall->decide($firstRequest)->isPass());
        $firewallResult = $firewall->decide($secondRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    public function testForwardedBracketedIpv6WithoutPortIsResolvedAsClientIp(): void
    {
        // The literal RFC 7239 IPv6 example: `for="[2001:db8::1]"` (no port).
        // BRACKETED_IPV6_PATTERN's optional `:port` group means this form
        // must be accepted alongside the with-port variant.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Two requests behind different trusted proxies, same bracketed IPv6
        // (no port). Resolver must produce the same throttle key.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', 'for="[2001:db8::42]"');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', 'for="[2001:db8::42]"');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testForwardedMixedChainResolvesBracketedIpv6AndBareIpv4(): void
    {
        // Single Forwarded header containing both a bracketed IPv6+port
        // entry and a bare IPv4 entry. Resolver walks right-to-left through
        // the for= values, skipping trusted hops, returning the first
        // untrusted entry — regardless of which form it takes.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        // Chain: bracketed IPv6 client, then trusted IPv4 proxy hop. Right-
        // to-left walk: 10.0.0.1 (trusted, skip), 2001:db8::42 (untrusted,
        // returned). Two requests share the bucket.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('Forwarded', 'for="[2001:db8::42]:9090", for=10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('Forwarded', 'for="[2001:db8::42]:9090", for=10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testForwardedRejectsValueWithStrayClosingBracket(): void
    {
        // A malformed `for=` value with a stray `]` but no matching `[`
        // (e.g. `for="203.0.113.1]:443"`) must be rejected by the parser
        // rather than silently parsed as `203.0.113.1`. The lookahead in
        // FORWARDED_FOR_PATTERN requires the value to end at a token boundary
        // — `]` is not one. With the malformed element being the only `for=`
        // entry, the chain becomes empty and the resolver falls back to
        // REMOTE_ADDR.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Two requests behind different trusted proxies, identical malformed
        // `for=` value. If the regex erroneously accepted it, both would
        // resolve to 203.0.113.1 and share the bucket → second throttled.
        // With the rejection, both fall back to their respective REMOTE_ADDRs
        // → different keys → second passes.
        $forwarded = 'for="203.0.113.1]:443"';

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertTrue(
            $firewall->decide($second)->isPass(),
            'Different REMOTE_ADDRs should give different buckets when malformed value is rejected',
        );
    }

    public function testMaxChainEntriesKeepsRightmostEntriesNotLeftmost(): void
    {
        // Sanity check that the parsed window includes the rightmost (authoritative)
        // entries when the chain length exceeds the cap, regardless of any leading
        // stuffing.
        //
        // Setup: maxChainEntries=2, trustedProxies=['10.0.0.0/8'].
        // XFF: <stuffed>, <stuffed>, 198.51.100.99, 10.0.0.1
        // Rightmost-2 window: [198.51.100.99, 10.0.0.1]. Walking right-to-left:
        // 10.0.0.1 is trusted (skip), 198.51.100.99 is untrusted -> client IP.
        //
        // If the parser instead kept the leftmost 2, the window would be the two
        // <stuffed> entries and the resolved IP would be one of those. Asserting
        // the rule throttles for 198.51.100.99 after one pass — but not for a
        // different value carried in the same leading slots — proves the
        // authoritative entries survive the truncation.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Forwarded-For'], 2);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '203.0.113.1, 203.0.113.2, 198.51.100.99, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass(), 'First call from 198.51.100.99 should pass');

        // Same authoritative tail, different leading stuffing. If the parser
        // were keeping the leftmost entries, this would resolve to a different
        // throttle key and pass again instead of getting throttled.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '192.0.2.55, 192.0.2.99, 198.51.100.99, 10.0.0.1');
        $this->assertSame(
            Outcome::THROTTLED,
            $firewall->decide($second)->outcome,
            'Second call from same authoritative tail must share the throttle bucket',
        );
    }

    public function testForwardedTruncationKeepsRightmostForValues(): void
    {
        // maxChainEntries=2 with a Forwarded chain of four `for=` values.
        // The resolver should keep the two rightmost — same direction as XFF.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded'], 2);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('Forwarded', 'for="203.0.113.1", for="203.0.113.2", for="198.51.100.99", for="10.0.0.1"');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Same authoritative tail with different leading stuffing must share the
        // throttle bucket — i.e. the rightmost two `for=` values are what's kept.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('Forwarded', 'for="192.0.2.55", for="192.0.2.99", for="198.51.100.99", for="10.0.0.1"');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testForwardedTruncationCollectsForValuesBeforeSlicing(): void
    {
        // Trailing forwarded-elements without `for=` (e.g., by-only) must not
        // crowd valid `for=` entries out of the truncation window. Pre-slicing
        // by element would leave only the by-only tail, which has no `for=`,
        // collapsing the chain to empty and falling back to REMOTE_ADDR.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded'], 2);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $forwarded = 'for="198.51.100.42", by="proxy1", by="proxy2"';

        // Two requests with the SAME `for=` value but different REMOTE_ADDR.
        // If `for=` is collected before slicing, both resolve to 198.51.100.42
        // and share the throttle bucket. If element-slicing happens first, both
        // chains are empty and the resolver falls back to REMOTE_ADDR, giving
        // two distinct keys and no shared bucket.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testResolverSkipsUnparseableChainEntries(): void
    {
        // A chain with garbage between trusted and untrusted entries should
        // step over the garbage (normalizeIp returns null → resolve continues)
        // rather than fall back to REMOTE_ADDR.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        // XFF: client 198.51.100.42, then a garbage entry, then trusted proxy.
        // Right-to-left walk: 10.0.0.1 (trusted, skip), "garbage" (null, skip),
        // 198.51.100.42 (untrusted, returned).
        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '198.51.100.42, not-an-ip, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Second request from same client IP — same throttle bucket, throttled.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '198.51.100.42, not-an-ip, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testNormalizeIpStripsIpv4PortSuffix(): void
    {
        // Some proxies emit "host:port" in XFF for IPv4 entries; normalizeIp()
        // must strip the port so the resolved client IP equals the bare IPv4.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        // First request: client emits with port suffix.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '198.51.100.7:47011, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Second request: bare IP, no port. Must share the throttle bucket —
        // proving that the port was stripped on the first resolve.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '198.51.100.7, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testAllTrustedChainFallsBackToRemoteAddr(): void
    {
        // Every hop in the XFF chain is trusted — the right-to-left walk
        // exhausts without finding an untrusted entry, falling back to the
        // direct peer (REMOTE_ADDR) at the end of resolve().
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // REMOTE_ADDR 10.0.0.1; both XFF entries inside the trusted range.
        // Resolved client IP must be 10.0.0.1 (the REMOTE_ADDR fallback).
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '10.0.0.2, 10.0.0.3');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Same REMOTE_ADDR, different (still-trusted) XFF entries. Sharing the
        // bucket proves resolve() landed on REMOTE_ADDR for both, not on a
        // chain entry.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '10.0.0.42, 10.0.0.99');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testEmptyOrCommasOnlyXffFallsBackToRemoteAddr(): void
    {
        // A malformed XFF that's effectively empty (`", ,"`) must not crash
        // and must fall back to REMOTE_ADDR rather than return null or an
        // arbitrary entry.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', ', , ,');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', ', , ,');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testForwardedObfuscatedIdentifiersAreSkipped(): void
    {
        // RFC 7239 §6 allows obfuscated identifiers (`unknown`, `_secret`) in
        // `for=`. They are not IPs — normalizeIp must reject them and the
        // walker must *skip and continue*, not skip and bail. A mixed chain
        // with an obfuscated rightmost entry and a valid IP to its left must
        // resolve to the valid IP, not REMOTE_ADDR.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Two requests behind DIFFERENT trusted proxies, same Forwarded chain:
        // `for="198.51.100.7", for=unknown`. Right-to-left walk: `unknown`
        // (null, skip), `198.51.100.7` (untrusted, returned). If the walker
        // bailed at the first skip, it would fall back to REMOTE_ADDR and the
        // two requests would land in different buckets.
        $forwarded = 'for="198.51.100.7", for=unknown';

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', $forwarded);
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testMultiInstanceXffIsFlattenedInReceiveOrder(): void
    {
        // PSR-7's withAddedHeader yields multiple header instances. The resolver
        // flattens every instance into one comma-separated chain in receive
        // order, then walks it right-to-left. Here the flattened chain is
        // "10.0.0.1, 198.51.100.5": the rightmost untrusted hop 198.51.100.5 is
        // the client, so both requests resolve to it and share the bucket.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '10.0.0.1')
            ->withAddedHeader('X-Forwarded-For', '198.51.100.5');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('X-Forwarded-For', '10.0.0.1')
            ->withAddedHeader('X-Forwarded-For', '198.51.100.5');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testMultiInstanceXffIsFlattenedRegardlessOfInstanceBoundaries(): void
    {
        // The resolver must NOT treat instance separation as a
        // security boundary. Two X-Forwarded-For instances "1.2.3.4" then the
        // trusted-proxy hop "10.0.0.1" are flattened to "1.2.3.4, 10.0.0.1" and
        // walked right-to-left: 10.0.0.1 is trusted (skip), 1.2.3.4 is the first
        // untrusted hop and is returned. This is identical to the folded form
        // "1.2.3.4, 10.0.0.1" sent as a single instance; folding does not
        // change the outcome.
        //
        // (A folded stack, nginx default, RFC 7230 §3.2.2, would deliver
        // exactly this single comma-joined value, so the previous "pick the last
        // instance" approach would have diverged between folded and unfolded
        // deployments. The trusted-hop walk is the only boundary that holds for
        // both.)
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Unfolded multi-instance form resolves to 1.2.3.4.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '1.2.3.4')
            ->withAddedHeader('X-Forwarded-For', '10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Folded single-instance form must resolve to the SAME 1.2.3.4 and share
        // the throttle bucket, proving the boundary is the walk, not the
        // instance split.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('X-Forwarded-For', '1.2.3.4, 10.0.0.1');
        $this->assertSame(
            Outcome::THROTTLED,
            $firewall->decide($second)->outcome,
            'Folded and unfolded XFF forms must resolve to the same client IP',
        );
    }

    public function testMultiInstanceForwardedIsFlattenedRegardlessOfInstanceBoundaries(): void
    {
        // Same flattening guarantee for the RFC 7239 `Forwarded` header. Two
        // instances `for="1.2.3.4"` then `for="10.0.0.1"` are flattened and
        // walked right-to-left: the trusted hop 10.0.0.1 is skipped, 1.2.3.4 is
        // the first untrusted hop. The folded single instance
        // `for="1.2.3.4", for="10.0.0.1"` must resolve identically.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', 'for="1.2.3.4"')
            ->withAddedHeader('Forwarded', 'for="10.0.0.1"');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('Forwarded', 'for="1.2.3.4", for="10.0.0.1"');
        $this->assertSame(
            Outcome::THROTTLED,
            $firewall->decide($second)->outcome,
            'Folded and unfolded Forwarded forms must resolve to the same client IP',
        );
    }

    public function testForwardedTakesPrecedenceOverXffWhenListedFirst(): void
    {
        // `allowedHeaders` ordering controls precedence: the first listed header
        // that's populated wins. With Forwarded first and both headers present
        // carrying different client IPs, Forwarded must win.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['Forwarded', 'X-Forwarded-For']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Two requests with the SAME Forwarded `for=` IP but DIFFERENT XFF IPs.
        // If Forwarded wins, both resolve to the Forwarded IP and share the
        // throttle bucket. If XFF wins, the two requests get different keys.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', 'for="198.51.100.7"')
            ->withHeader('X-Forwarded-For', '203.0.113.1, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('Forwarded', 'for="198.51.100.7"')
            ->withHeader('X-Forwarded-For', '203.0.113.99, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIpv4MappedIpv6Forms(): iterable
    {
        yield 'dotted form' => ['::ffff:198.51.100.7'];
        // 198.51.100.7 = 0xc6.0x33.0x64.0x07
        yield 'hex form' => ['::ffff:c633:6407'];
        yield 'uppercase hex form' => ['::FFFF:C633:6407'];
    }

    #[DataProvider('provideIpv4MappedIpv6Forms')]
    public function testIpv4MappedIpv6IsCanonicalisedToBareIpv4(string $mappedForm): void
    {
        // A client appearing both as bare IPv4 and as ::ffff:-mapped IPv6 must
        // resolve to the same throttle bucket — normalizeIp() canonicalises
        // IPv4-mapped IPv6 (regardless of textual form) down to plain IPv4 so
        // an attacker cannot split their bucket via dual representation.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $remote = ['REMOTE_ADDR' => '10.0.0.1'];

        // First request: client in IPv4-mapped IPv6 form.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', $mappedForm . ', 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Second request: same client in bare IPv4 form. Bucket must be shared.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', $remote))
            ->withHeader('X-Forwarded-For', '198.51.100.7, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testIsTrustedMatchesBareIpProxyByStringEquality(): void
    {
        // trustedProxies entries without a slash are matched by exact string
        // equality (the non-CIDR branch in isTrusted). Cover that branch
        // explicitly — the other tests configure CIDR ranges.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.5']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // REMOTE_ADDR 10.0.0.5 — must match the bare-IP entry exactly. XFF
        // chain resolves through to the untrusted client (198.51.100.7).
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.5']))
            ->withHeader('X-Forwarded-For', '198.51.100.7, 10.0.0.5');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.5']))
            ->withHeader('X-Forwarded-For', '198.51.100.7, 10.0.0.5');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testResolverReturnsNullWhenRemoteAddrIsMissing(): void
    {
        // No REMOTE_ADDR → resolve() must return null instead of guessing.
        // Tested directly because Firewall would simply not key the throttle
        // and the failure mode would be invisible.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);

        $emptyServerParams = new ServerRequest('GET', '/', [], null, '1.1', []);
        $this->assertNull($trustedProxyResolver->resolve($emptyServerParams));

        $blankRemoteAddr = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '']);
        $this->assertNull($trustedProxyResolver->resolve($blankRemoteAddr));
    }

    public function testUnknownAllowedHeaderFallsBackToRemoteAddr(): void
    {
        // Only `X-Forwarded-For` and `Forwarded` are recognised. Any other
        // header name in `allowedHeaders` (typo, X-Real-IP, etc.) is silently
        // ignored and the resolver falls back to REMOTE_ADDR.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Real-IP']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        // Both XFF and X-Real-IP are populated; neither is consulted because
        // `X-Real-IP` is not a recognised name and XFF is not in allowedHeaders.
        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Real-IP', '198.51.100.7')
            ->withHeader('X-Forwarded-For', '203.0.113.1, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        // Same REMOTE_ADDR with different X-Real-IP and XFF. If either header
        // were honoured, the two requests would land in different buckets.
        // They share the bucket because both fall back to REMOTE_ADDR.
        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Real-IP', '203.0.113.99')
            ->withHeader('X-Forwarded-For', '198.51.100.99, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    public function testEmptyXffHeaderFallsBackToRemoteAddrWhenRemoteTrusted(): void
    {
        // REMOTE_ADDR is trusted and `X-Forwarded-For` is the only allowed
        // header — when the header is absent, extractFromXForwardedFor()
        // returns [] and the resolver must fall back to REMOTE_ADDR rather
        // than null. This covers the empty-header arm of the match dispatch.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Forwarded-For']);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNonPositiveMaxChainEntries(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-5];
    }

    #[DataProvider('provideNonPositiveMaxChainEntries')]
    public function testNonPositiveMaxChainEntriesDoesNotCrashAndStillResolves(int $maxChainEntries): void
    {
        // The constructor clamps maxChainEntries to >= 1 so that non-positive
        // values don't degenerate the parser (array_slice / right-to-left
        // bounds). This test confirms construction with 0 / -5 is accepted
        // and produces sensible resolution — it does not fully mutation-pin
        // the clamp itself, because `array_slice(-0)` happens to return the
        // full array and `array_slice(5)` returns empty, both of which yield
        // the same observable outcome (shared REMOTE_ADDR bucket) on this
        // setup as the clamped behaviour.
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Forwarded-For'], $maxChainEntries);
        $config = new Config(new InMemoryCache());
        $config->throttles->add('by_client', 1, 30, KeyExtractors::clientIp($trustedProxyResolver));

        $firewall = new Firewall($config);

        $first = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '198.51.100.5, 10.0.0.1');
        $this->assertTrue($firewall->decide($first)->isPass());

        $second = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Forwarded-For', '198.51.100.5, 10.0.0.1');
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($second)->outcome);
    }
}
