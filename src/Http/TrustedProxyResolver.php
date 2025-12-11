<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves the originating client IP when running behind trusted proxies.
 *
 * Security model:
 * - Only consults proxy headers when the direct peer (REMOTE_ADDR) is trusted.
 * - Walks X-Forwarded-For (or Forwarded) from right to left, skipping trusted proxy hops.
 * - Returns the first untrusted address in the chain; falls back to REMOTE_ADDR when uncertain.
 *
 * Notes:
 * - IPv4 and IPv6 CIDR ranges are supported (e.g., 10.0.0.0/8, 2001:db8::/32).
 */
final readonly class TrustedProxyResolver
{
    /** @var list<string> */
    private array $normalizedAllowedHeaders;

    private int $normalizedMaxChainEntries;

    /**
     * @param list<string> $trustedProxies List of trusted proxies as IP addresses or CIDR ranges (IPv4/IPv6)
     * @param list<string> $allowedHeaders List of header names (case-insensitive) that may contain client IP chains
     */
    public function __construct(
        private array $trustedProxies,
        private array $allowedHeaders = ['X-Forwarded-For', 'Forwarded'],
        private int $maxChainEntries = 50,
    ) {
        $this->normalizedAllowedHeaders = array_values(array_map('strtolower', $this->allowedHeaders));
        $this->normalizedMaxChainEntries = max(1, $this->maxChainEntries);
    }

    public function resolve(ServerRequestInterface $serverRequest): ?string
    {
        $remoteAddr = $this->normalizeIp((string)($serverRequest->getServerParams()['REMOTE_ADDR'] ?? ''));
        if ($remoteAddr === null) {
            return null;
        }

        // Only trust headers if the direct peer is trusted
        $remoteTrusted = $this->isTrusted($remoteAddr);
        if (!$remoteTrusted) {
            return $remoteAddr;
        }

        $chain = $this->extractChain($serverRequest);
        if ($chain === []) {
            return $remoteAddr;
        }

        // Walk from right (closest to us) to left
        for ($i = count($chain) - 1; $i >= 0; --$i) {
            $ip = $this->normalizeIp($chain[$i]);
            if ($ip === null) {
                // Skip unparsable values
                continue;
            }

            if ($this->isTrusted($ip)) {
                // still within trusted proxy chain; move left
                continue;
            }

            // First untrusted hop is the client IP
            return $ip;
        }

        // If all hops were trusted or unparsable, fall back to REMOTE_ADDR
        return $remoteAddr;
    }

    /**
     * @return list<string>
     */
    private function extractChain(ServerRequestInterface $serverRequest): array
    {
        $ips = [];

        foreach ($this->normalizedAllowedHeaders as $normalizedAllowedHeader) {
            if ($normalizedAllowedHeader === 'x-forwarded-for') {
                $xff = $serverRequest->getHeaderLine('X-Forwarded-For');
                if ($xff !== '') {
                    $parts = array_map('trim', explode(',', $xff));
                    foreach ($parts as $part) {
                        if ($part === '') {
                            continue;
                        }

                        // Remove quotes and brackets if any
                        $part = trim($part, " \"'[]");
                        // Strip port for IPv4 host:port (avoid breaking IPv6 addresses)
                        if (preg_match('/^[0-9.]+:\\d+$/', $part) === 1) {
                            $part = explode(':', $part, 2)[0];
                        }

                        $ips[] = $part;
                        if (count($ips) >= $this->normalizedMaxChainEntries) {
                            return $ips;
                        }
                    }

                    return $ips;
                }
            } elseif ($normalizedAllowedHeader === 'forwarded') {
                $fwd = $serverRequest->getHeaderLine('Forwarded');
                if ($fwd !== '') {
                    // Split by commas into elements
                    $elements = array_map('trim', explode(',', $fwd));
                    foreach ($elements as $element) {
                        if ($element === '') {
                            continue;
                        }

                        // Find for= token
                        if (preg_match('/(?:^|;| )for=\"?\[?([^;,\"]+)]?\"?/i', $element, $m) === 1) {
                            $candidate = $m[1];
                            $candidate = trim($candidate, " \"'[]");
                            if (preg_match('/^[0-9.]+:\\d+$/', $candidate) === 1) {
                                $candidate = explode(':', $candidate, 2)[0];
                            }

                            $ips[] = $candidate;
                            if (count($ips) >= $this->normalizedMaxChainEntries) {
                                return $ips;
                            }
                        }
                    }

                    return $ips;
                }
            }
        }

        return [];
    }

    private function isTrusted(string $ip): bool
    {
        foreach ($this->trustedProxies as $trustedProxy) {
            $trustedProxy = trim($trustedProxy);
            if ($trustedProxy === '') {
                continue;
            }

            if (str_contains($trustedProxy, '/')) {
                if ($this->ipInCidr($ip, $trustedProxy)) {
                    return true;
                }

                continue;
            }

            if ($ip === $trustedProxy) {
                return true;
            }
        }

        return false;
    }

    private function normalizeIp(string $ip): ?string
    {
        $ip = trim($ip);
        if ($ip === '') {
            return null;
        }

        // Remove surrounding brackets for IPv6
        $ip = trim($ip, '[]');
        // Strip IPv4 port suffix if present
        if (preg_match('/^[0-9.]+:\\d+$/', $ip) === 1) {
            $ip = explode(':', $ip, 2)[0];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return null;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr, 2) + [null, null];
        if ($subnet === null || $mask === null) {
            return false;
        }

        $mask = (int) $mask;
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $maxBits = strlen($ipBin) * 8;
        if ($mask < 0 || $mask > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($mask, 8);
        $remainingBits = $mask % 8;

        if ($fullBytes > 0 && strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $maskByte = (0xFF00 >> $remainingBits) & 0xFF;
        $ipByte = ord($ipBin[$fullBytes]) & $maskByte;
        $subnetByte = ord($subnetBin[$fullBytes]) & $maskByte;

        return $ipByte === $subnetByte;
    }
}
