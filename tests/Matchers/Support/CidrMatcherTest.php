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

    public function testIpv4MappedIpv6DoesNotMatchIpv4Cidr(): void
    {
        // IPv4-mapped IPv6 (::ffff:10.0.0.1) is a different address family
        // and does NOT match IPv4 CIDRs — this is by design
        $compiled = CidrMatcher::compile('10.0.0.0/8');
        $this->assertNotNull($compiled);

        $mappedBinary = @inet_pton('::ffff:10.0.0.1');
        $this->assertNotFalse($mappedBinary);
        $this->assertFalse(CidrMatcher::matches($mappedBinary, $compiled));
    }
}
