<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers\Support;

use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use PHPUnit\Framework\TestCase;

final class CidrMatcherTest extends TestCase
{
    public function testCompileValidIpv4Cidr(): void
    {
        $compiled = CidrMatcher::compile('192.168.0.0/16');
        $this->assertNotNull($compiled);
        $this->assertSame(16, $compiled['bits']);
    }

    public function testCompileValidIpv6Cidr(): void
    {
        $compiled = CidrMatcher::compile('2001:db8::/32');
        $this->assertNotNull($compiled);
        $this->assertSame(32, $compiled['bits']);
    }

    public function testCompileInvalidCidr(): void
    {
        $this->assertNull(CidrMatcher::compile('not-a-cidr'));
        $this->assertNull(CidrMatcher::compile('192.168.0.0/33'));
        $this->assertNull(CidrMatcher::compile('192.168.0.0/-1'));
    }

    public function testContainsIpv4InRange(): void
    {
        $this->assertTrue(CidrMatcher::containsIp('10.1.2.3', '10.0.0.0/8'));
        $this->assertTrue(CidrMatcher::containsIp('10.255.255.255', '10.0.0.0/8'));
        $this->assertFalse(CidrMatcher::containsIp('11.0.0.1', '10.0.0.0/8'));
    }

    public function testContainsIpv6InRange(): void
    {
        $this->assertTrue(CidrMatcher::containsIp('2001:0db8::1', '2001:db8::/32'));
        $this->assertFalse(CidrMatcher::containsIp('2001:0db9::1', '2001:db8::/32'));
    }

    public function testAddressFamilyMismatch(): void
    {
        $this->assertFalse(CidrMatcher::containsIp('::1', '10.0.0.0/8'));
        $this->assertFalse(CidrMatcher::containsIp('10.0.0.1', '2001:db8::/32'));
    }

    public function testContainsIpWithInvalidInputs(): void
    {
        $this->assertFalse(CidrMatcher::containsIp('not-an-ip', '10.0.0.0/8'));
        $this->assertFalse(CidrMatcher::containsIp('10.0.0.1', 'not-a-cidr'));
    }

    public function testSlash32MatchesExactIp(): void
    {
        $this->assertTrue(CidrMatcher::containsIp('10.0.0.1', '10.0.0.1/32'));
        $this->assertFalse(CidrMatcher::containsIp('10.0.0.2', '10.0.0.1/32'));
    }

    public function testSlash0MatchesEverything(): void
    {
        $this->assertTrue(CidrMatcher::containsIp('1.2.3.4', '0.0.0.0/0'));
        $this->assertTrue(CidrMatcher::containsIp('255.255.255.255', '0.0.0.0/0'));
    }

    public function testSlash24Boundary(): void
    {
        $this->assertTrue(CidrMatcher::containsIp('192.168.1.0', '192.168.1.0/24'));
        $this->assertTrue(CidrMatcher::containsIp('192.168.1.255', '192.168.1.0/24'));
        $this->assertFalse(CidrMatcher::containsIp('192.168.2.0', '192.168.1.0/24'));
    }

    public function testIpv4MappedIpv6MatchesIpv4Cidr(): void
    {
        // Dual-stack hosts present an IPv4 client as ::ffff:10.0.0.1. The binary
        // is collapsed to the embedded IPv4 address so a single IPv4 CIDR rule
        // matches either presentation.
        $compiled = CidrMatcher::compile('10.0.0.0/8');
        $this->assertNotNull($compiled);

        $mappedBinary = @inet_pton('::ffff:10.0.0.1');
        $this->assertNotFalse($mappedBinary);
        $this->assertTrue(CidrMatcher::matches($mappedBinary, $compiled));

        $outOfRange = @inet_pton('::ffff:11.0.0.1');
        $this->assertNotFalse($outOfRange);
        $this->assertFalse(CidrMatcher::matches($outOfRange, $compiled));
    }

    public function testIpv4MappedIpv6CidrIsCanonicalisedToIpv4(): void
    {
        // An IPv4-mapped IPv6 CIDR collapses to its embedded IPv4 form (prefix
        // length minus the 96-bit `::ffff:` prefix) so it matches the
        // canonicalised peer, mirroring the exact-match path. `::ffff:10.0.0.0/120`
        // is therefore equivalent to `10.0.0.0/24`.
        $compiled = CidrMatcher::compile('::ffff:10.0.0.0/120');
        $this->assertNotNull($compiled);

        $this->assertTrue(CidrMatcher::matches((string) inet_pton('::ffff:10.0.0.1'), $compiled));
        $this->assertTrue(CidrMatcher::matches((string) inet_pton('10.0.0.42'), $compiled));
        $this->assertFalse(CidrMatcher::matches((string) inet_pton('10.0.1.1'), $compiled));
    }

    public function testCanonicalizeIpCollapsesIpv4MappedIpv6(): void
    {
        $this->assertSame('1.2.3.4', CidrMatcher::canonicalizeIp('::ffff:1.2.3.4'));
        // Plain IPv4 and already-canonical IPv6 round-trip to themselves;
        // unparseable input is returned unchanged.
        $this->assertSame('1.2.3.4', CidrMatcher::canonicalizeIp('1.2.3.4'));
        $this->assertSame('::1', CidrMatcher::canonicalizeIp('::1'));
        $this->assertSame('not-an-ip', CidrMatcher::canonicalizeIp('not-an-ip'));
    }

    public function testCanonicalizeIpNormalizesGenuineIpv6AltForms(): void
    {
        // Zero-padded, expanded, and mixed-case genuine IPv6 all collapse to the
        // compressed lowercase form, so text-comparing matchers treat every
        // spelling of the same address as equal.
        $this->assertSame('2001:db8::1', CidrMatcher::canonicalizeIp('2001:0DB8::1'));
        $this->assertSame('2001:db8::1', CidrMatcher::canonicalizeIp('2001:db8:0:0:0:0:0:1'));
        $this->assertSame('2001:db8::1', CidrMatcher::canonicalizeIp('2001:DB8::1'));
        $this->assertSame(
            CidrMatcher::canonicalizeIp('2001:0DB8::1'),
            CidrMatcher::canonicalizeIp('2001:db8::1'),
        );
    }
}
