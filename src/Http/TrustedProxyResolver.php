<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Flowd\Phirewall\Matchers\Support\CidrMatcher;
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
    /**
     * RFC 7239 `for=` parameter extractor. Matches the parameter at the start of
     * a forwarded-element or after `;`/space, with optional quoting and optional
     * IPv6 brackets. The captured value still passes through normalizeIp() for
     * bracket / port / validation. The character class excludes the parameter
     * separators (`;`/`,`), the quote character, and all whitespace, so a
     * malformed element like `for="1.2.3.4 ;proto=https` won't over-capture
     * past token boundaries.
     */
    private const FORWARDED_FOR_PATTERN = '/(?:^|;| )for=\"?\[?([^;,\"\s]+)]?\"?/i';

    /** @var list<string> */
    private array $normalizedAllowedHeaders;

    /** @var list<string> */
    private array $normalizedTrustedProxies;

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
        $this->normalizedTrustedProxies = array_values(array_filter(
            array_map('trim', $this->trustedProxies),
            static fn(string $proxy): bool => $proxy !== '',
        ));
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
     * Walks the configured `allowedHeaders` in order and returns the first
     * non-empty chain. Unknown header names are silently ignored — only
     * `X-Forwarded-For` and `Forwarded` are recognised.
     *
     * @return list<string>
     */
    private function extractChain(ServerRequestInterface $serverRequest): array
    {
        foreach ($this->normalizedAllowedHeaders as $normalizedAllowedHeader) {
            $chain = match ($normalizedAllowedHeader) {
                'x-forwarded-for' => $this->extractFromXForwardedFor($serverRequest),
                'forwarded' => $this->extractFromForwarded($serverRequest),
                default => [],
            };

            if ($chain !== []) {
                return $chain;
            }
        }

        return [];
    }

    /**
     * @return list<string>
     */
    private function extractFromXForwardedFor(ServerRequestInterface $serverRequest): array
    {
        $header = $serverRequest->getHeaderLine('X-Forwarded-For');
        if ($header === '') {
            return [];
        }

        // Keep only the rightmost N entries. The XFF chain is appended by each
        // proxy hop, so the entries closest to us — the ones added by trusted
        // proxies — sit at the right end. Truncating from the left preserves
        // that authoritative tail when the header carries more than
        // `maxChainEntries` values.
        return array_slice($this->splitElements($header), -$this->normalizedMaxChainEntries);
    }

    /**
     * @return list<string>
     */
    private function extractFromForwarded(ServerRequestInterface $serverRequest): array
    {
        $header = $serverRequest->getHeaderLine('Forwarded');
        if ($header === '') {
            return [];
        }

        // A chain entry here is a `for=` value, not a forwarded-element, so
        // slicing elements upfront would drop valid `for=` entries when
        // trailing elements are `by=`-only. Walk right-to-left and stop once
        // `maxChainEntries` `for=` matches are collected — this preserves the
        // rightmost-N semantics while bounding regex work under header stuffing.
        $ips = [];
        $elements = $this->splitElements($header);
        for ($i = count($elements) - 1; $i >= 0; --$i) {
            if (preg_match(self::FORWARDED_FOR_PATTERN, $elements[$i], $matches) === 1) {
                $ips[] = $matches[1];
                if (count($ips) >= $this->normalizedMaxChainEntries) {
                    break;
                }
            }
        }

        return array_reverse($ips);
    }

    /**
     * Split a comma-separated header value, trim parts, drop empties.
     *
     * @return list<string>
     */
    private function splitElements(string $headerValue): array
    {
        return array_values(array_filter(
            array_map('trim', explode(',', $headerValue)),
            static fn(string $part): bool => $part !== '',
        ));
    }

    private function isTrusted(string $ip): bool
    {
        foreach ($this->normalizedTrustedProxies as $normalizedTrustedProxy) {
            if (str_contains($normalizedTrustedProxy, '/')) {
                if (CidrMatcher::containsIp($ip, $normalizedTrustedProxy)) {
                    return true;
                }

                continue;
            }

            if ($ip === $normalizedTrustedProxy) {
                return true;
            }
        }

        return false;
    }

    private function normalizeIp(string $ip): ?string
    {
        // Strip whitespace, surrounding quotes, and IPv6 brackets. Bracket
        // stripping must precede validation so plain `[2001:db8::1]` passes
        // FILTER_VALIDATE_IP, and must precede the IPv4:port check below so
        // the regex sees a bare host.
        $ip = trim($ip, " \t\n\r\0\x0B\"'[]");
        if ($ip === '') {
            return null;
        }

        // Strip IPv4 port suffix if present (IPv6 addresses contain colons and
        // are skipped by this pattern).
        if (preg_match('/^[0-9.]+:\\d+$/', $ip) === 1) {
            $ip = explode(':', $ip, 2)[0];
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        // Canonicalise IPv4-mapped IPv6 ("::ffff:1.2.3.4", "::ffff:c000:0201")
        // to the bare IPv4 form so the same client doesn't end up in two
        // throttle / fail2ban / allow2ban buckets via dual representation.
        $packed = inet_pton($ip);
        if (
            $packed !== false
            && strlen($packed) === 16
            && str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")
        ) {
            $ipv4 = inet_ntop(substr($packed, 12));
            if ($ipv4 !== false) {
                return $ipv4;
            }
        }

        return $ip;
    }
}
