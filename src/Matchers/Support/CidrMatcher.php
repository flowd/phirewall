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

        return ['network' => $networkBinary, 'bits' => $prefixLength];
    }

    /**
     * Note: IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) will NOT match IPv4 CIDRs.
     * If your server presents REMOTE_ADDR as ::ffff:x.x.x.x, write your rules as
     * IPv6 CIDRs or configure your server to present plain IPv4 addresses.
     *
     * @param array{network: string, bits: int} $compiled
     */
    public static function matches(string $ipBinary, array $compiled): bool
    {
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
