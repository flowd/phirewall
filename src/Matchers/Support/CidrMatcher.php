<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers\Support;

/**
 * Shared CIDR compilation and matching logic.
 *
 * @internal Shared infrastructure for phirewall internals. Not part of the public API.
 */
final class CidrMatcher
{
    /**
     * IPv4-mapped IPv6 prefix: the first 12 bytes of any IPv4-mapped IPv6
     * binary (`::ffff:x.x.x.x`). Used to collapse those forms to the
     * embedded 4-byte IPv4 address so a single rule matches both textual
     * representations on dual-stack hosts.
     */
    private const IPV4_MAPPED_PREFIX = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

    /**
     * @return array{network: string, bits: int}|null
     */
    public static function compile(string $cidr): ?array
    {
        [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $prefixLength = is_numeric($bits) ? (int) $bits : -1;
        $networkBinary = @inet_pton((string) $network);
        if ($networkBinary === false) {
            return null;
        }

        $maxBits = strlen($networkBinary) * 8;
        if ($prefixLength < 0 || $prefixLength > $maxBits) {
            return null;
        }

        // Canonicalize an IPv4-mapped IPv6 network (e.g. `::ffff:10.0.0.0/120`)
        // to its embedded IPv4 form so it matches the peer canonicalisation in
        // matches(), which collapses IPv4-mapped peers to 4 bytes. The leading
        // 96 bits are the `::ffff:` prefix, so the prefix length drops by 96.
        // Prefixes that reach into the mapped prefix itself (< 96) are left as
        // a 16-byte network — collapsing them is not meaningful.
        $canonicalNetwork = self::canonicalizeBinary($networkBinary);
        if ($canonicalNetwork !== $networkBinary && $prefixLength >= 96) {
            $networkBinary = $canonicalNetwork;
            $prefixLength -= 96;
        }

        return ['network' => $networkBinary, 'bits' => $prefixLength];
    }

    /**
     * Collapse an IPv4-mapped IPv6 binary (`::ffff:x.x.x.x`) to its embedded
     * 4-byte IPv4 binary. Any other binary is returned unchanged. This lets a
     * single IPv4 rule match clients that a dual-stack host presents in either
     * form.
     */
    public static function canonicalizeBinary(string $ipBinary): string
    {
        if (strlen($ipBinary) === 16 && str_starts_with($ipBinary, self::IPV4_MAPPED_PREFIX)) {
            return substr($ipBinary, 12);
        }

        return $ipBinary;
    }

    /**
     * Canonicalize an IP address string for exact-match comparisons. Any valid
     * IP is round-tripped through `inet_pton`/`inet_ntop` so every alternate
     * spelling of the same address collapses to one canonical text form:
     * IPv4-mapped IPv6 (`::ffff:x.x.x.x`) becomes plain IPv4, and genuine IPv6
     * (zero-padded, expanded, or mixed-case, e.g. `2001:0DB8::1`) becomes the
     * compressed lowercase form (`2001:db8::1`). This lets every text-comparing
     * call site (file/snapshot blocklist matchers) treat all spellings of an
     * address as equal, matching the binary-keyed behaviour of `IpMatcher`.
     * Strings that are not parseable IPs are returned unchanged.
     */
    public static function canonicalizeIp(string $ip): string
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return $ip;
        }

        $text = @inet_ntop(self::canonicalizeBinary($binary));

        return $text === false ? $ip : $text;
    }

    /**
     * The client IP is canonicalized first, so IPv4 CIDRs also match clients
     * presented as IPv4-mapped IPv6 (`::ffff:x.x.x.x`) by a dual-stack host.
     *
     * @param array{network: string, bits: int} $compiled
     */
    public static function matches(string $ipBinary, array $compiled): bool
    {
        $ipBinary = self::canonicalizeBinary($ipBinary);

        if (strlen($ipBinary) !== strlen($compiled['network'])) {
            return false;
        }

        $fullBytes = intdiv($compiled['bits'], 8);
        $remainingBits = $compiled['bits'] % 8;

        if ($fullBytes > 0 && strncmp($ipBinary, $compiled['network'], $fullBytes) !== 0) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF00 >> $remainingBits) & 0xFF;
        return (ord($ipBinary[$fullBytes]) & $mask) === (ord($compiled['network'][$fullBytes]) & $mask);
    }

    public static function containsIp(string $ipAddress, string $cidr): bool
    {
        $compiled = self::compile($cidr);
        if ($compiled === null) {
            return false;
        }

        $ipBinary = @inet_pton($ipAddress);
        if ($ipBinary === false) {
            return false;
        }

        return self::matches($ipBinary, $compiled);
    }

}
