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
 * - IPv4 CIDR ranges are supported (e.g., 10.0.0.0/8). IPv6 CIDR is not implemented; exact IPv6 matches work.
 */
final class TrustedProxyResolver
{
    /**
     * @param list<string> $trustedProxies List of trusted proxies as IPv4/IPv6 addresses or IPv4 CIDR ranges
     */
    public function __construct(
        private readonly array $trustedProxies,
        private readonly string $xffHeader = 'X-Forwarded-For',
    ) {
    }

    public function resolve(ServerRequestInterface $request): ?string
    {
        $remoteAddr = $this->normalizeIp((string)($request->getServerParams()['REMOTE_ADDR'] ?? ''));
        if ($remoteAddr === null) {
            return null;
        }

        // Only trust headers if the direct peer is trusted
        $remoteTrusted = $this->isTrusted($remoteAddr);
        if (!$remoteTrusted) {
            return $remoteAddr;
        }

        $chain = $this->extractChain($request);
        if ($chain === []) {
            return $remoteAddr;
        }

        // Walk from right (closest to us) to left
        for ($i = count($chain) - 1; $i >= 0; $i--) {
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
    private function extractChain(ServerRequestInterface $request): array
    {
        $xff = $request->getHeaderLine($this->xffHeader);
        if ($xff !== '') {
            $parts = array_map('trim', explode(',', $xff));
            $ips = [];
            foreach ($parts as $p) {
                if ($p === '') {
                    continue;
                }
                // Remove quotes and brackets if any
                $p = trim($p, " \"'[]");
                // Strip port for IPv4 host:port (avoid breaking IPv6 addresses)
                if (preg_match('/^[0-9.]+:[0-9]+$/', $p) === 1) {
                    $p = explode(':', $p, 2)[0];
                }
                $ips[] = $p;
            }
            return $ips;
        }

        // Fallback to RFC 7239 Forwarded header parsing
        $fwd = $request->getHeaderLine('Forwarded');
        if ($fwd !== '') {
            $ips = [];
            // Split by commas into elements
            $elements = array_map('trim', explode(',', $fwd));
            foreach ($elements as $el) {
                if ($el === '') {
                    continue;
                }
                // Find for= token
                if (preg_match('/(?:^|;| )for=\"?\[?([^;,"]+)\]?\"?/i', $el, $m) === 1) {
                    $candidate = $m[1];
                    $candidate = trim($candidate, " \"'[]");
                    if (preg_match('/^[0-9.]+:[0-9]+$/', $candidate) === 1) {
                        $candidate = explode(':', $candidate, 2)[0];
                    }
                    $ips[] = $candidate;
                }
            }
            return $ips;
        }

        return [];
    }

    private function isTrusted(string $ip): bool
    {
        foreach ($this->trustedProxies as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            // CIDR IPv4
            if (str_contains($entry, '/')) {
                if ($this->ipv4InCidr($ip, $entry)) {
                    return true;
                }
                continue;
            }
            // Exact match
            if ($ip === $entry) {
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
        if (preg_match('/^[0-9.]+:[0-9]+$/', $ip) === 1) {
            $ip = explode(':', $ip, 2)[0];
        }
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        return null;
    }

    private function ipv4InCidr(string $ip, string $cidr): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        [$subnet, $mask] = explode('/', $cidr, 2) + [null, null];
        if ($subnet === null || $mask === null) {
            return false;
        }
        if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        $mask = (int) $mask;
        if ($mask < 0 || $mask > 32) {
            return false;
        }
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        $maskLong = $mask === 0 ? 0 : (~0 << (32 - $mask)) & 0xFFFFFFFF;
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
