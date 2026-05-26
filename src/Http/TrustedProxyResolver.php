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
     * RFC 7239 `for=` parameter extractor. Matches the parameter at the start
     * of a forwarded-element or after `;`/space. The value is one of:
     *
     * - `[ipv6](:port)?` — RFC 7239 form for IPv6 hosts (the bracketed form
     *   may carry an optional port; the captured group keeps both for
     *   normalizeIp() to strip).
     * - a bare value (IPv4, IPv4:port, IPv6 without port, or RFC 7239 §6
     *   obfuscated identifier) containing no `;`, `,`, `"`, whitespace, or
     *   brackets.
     *
     * The trailing positive lookahead `(?=[\s;,"]|$)` requires the value to
     * end at a valid token boundary, so a malformed element like
     * `for="203.0.113.1]:443"` (stray `]` without a matching `[`) is rejected
     * outright rather than silently parsed as `203.0.113.1`.
     */
    private const FORWARDED_FOR_PATTERN = '/(?:^|;| )for=\"?(\[[^\[\]\s]+](?::\d+)?|[^;,\"\s\[\]]+)(?=[\s;,\"]|$)/i';

    /**
     * Bracketed IPv6 + optional port — RFC 7239 form for IPv6 hosts and the
     * shape some proxies emit in X-Forwarded-For. Captures the address only;
     * the trailing port is discarded by normalizeIp() before validation.
     */
    private const BRACKETED_IPV6_PATTERN = '/^\[([^\]]+)](?::\d+)?$/';

    /** @var list<string> */
    private array $normalizedAllowedHeaders;

    private int $normalizedMaxChainEntries;

    /**
     * Set of canonical inet_pton-binary forms for the bare-IP entries of
     * $trustedProxies. Keying by binary handles IPv6 alt-forms (compressed,
     * expanded, mixed case) uniformly via inet_pton normalisation.
     *
     * @var array<string, true>
     */
    private array $trustedProxyBinaries;

    /** @var list<string> CIDR entries of $trustedProxies, kept as strings for CidrMatcher. */
    private array $trustedProxyCidrs;

    /**
     * @param list<string> $trustedProxies List of trusted proxies as IP addresses or CIDR ranges (IPv4/IPv6)
     * @param list<string> $allowedHeaders Header names (case-insensitive) the resolver should consult for the
     *                                     client-IP chain, walked in order until one is non-empty. Only
     *                                     `X-Forwarded-For` and `Forwarded` (RFC 7239) are recognised; other
     *                                     names are silently ignored. Defaults to `['X-Forwarded-For']` — pass
     *                                     `['Forwarded']` or `['Forwarded', 'X-Forwarded-For']` explicitly when
     *                                     the upstream proxy emits RFC 7239 instead of (or in addition to) XFF.
     */
    public function __construct(
        private array $trustedProxies,
        private array $allowedHeaders = ['X-Forwarded-For'],
        private int $maxChainEntries = 50,
    ) {
        $this->normalizedAllowedHeaders = array_values(array_map('strtolower', $this->allowedHeaders));
        $this->normalizedMaxChainEntries = max(1, $this->maxChainEntries);

        $bareBinaries = [];
        $cidrs = [];
        foreach ($this->trustedProxies as $trustedProxy) {
            $trustedProxy = trim($trustedProxy);
            if ($trustedProxy === '') {
                continue;
            }

            if (str_contains($trustedProxy, '/')) {
                $cidrs[] = $trustedProxy;
                continue;
            }

            $binary = @inet_pton($trustedProxy);
            if ($binary !== false) {
                $bareBinaries[CidrMatcher::canonicalizeBinary($binary)] = true;
            }
        }

        $this->trustedProxyBinaries = $bareBinaries;
        $this->trustedProxyCidrs = $cidrs;
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
        // Read only the last received `X-Forwarded-For` header instance rather
        // than flattening every instance with getHeaderLine(). PSR-7 stacks
        // preserve receive order, so the last instance is the one the
        // closest-to-us (trusted) proxy appended; an attacker who prepends a
        // duplicate header line lands in an earlier instance and is ignored.
        $header = $this->lastNonEmptyHeaderValue($serverRequest->getHeader('X-Forwarded-For'));
        if ($header === null) {
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
        // As with X-Forwarded-For, consult only the last received `Forwarded`
        // header instance so a prepended duplicate header line cannot inject a
        // spoofed `for=` value ahead of the proxy-appended chain.
        $header = $this->lastNonEmptyHeaderValue($serverRequest->getHeader('Forwarded'));
        if ($header === null) {
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

    /**
     * Return the last non-empty value from a PSR-7 getHeader() array, or null
     * if every value is empty / the array is empty. Used so a duplicate header
     * instance appended by the closest-to-us proxy is preferred over earlier
     * instances, which may have been forwarded verbatim from the inbound
     * request and are therefore attacker-controlled.
     *
     * @param array<string> $values
     */
    private function lastNonEmptyHeaderValue(array $values): ?string
    {
        $list = array_values($values);
        for ($index = count($list) - 1; $index >= 0; --$index) {
            $value = trim($list[$index]);
            if ($value !== '') {
                return $value;
            }
        }

        return null;
    }

    private function isTrusted(string $ip): bool
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return false;
        }

        // Trusted-proxy binaries are stored canonicalised (IPv4-mapped IPv6
        // collapsed to its embedded IPv4 by CidrMatcher::canonicalizeBinary), so
        // one canonical lookup matches a rule written as IPv4 against an
        // IPv4-mapped IPv6 peer presentation and vice-versa.
        if (isset($this->trustedProxyBinaries[CidrMatcher::canonicalizeBinary($binary)])) {
            return true;
        }

        foreach ($this->trustedProxyCidrs as $trustedProxyCidr) {
            if (CidrMatcher::containsIp($ip, $trustedProxyCidr)) {
                return true;
            }
        }

        return false;
    }

    private function normalizeIp(string $ip): ?string
    {
        // Strip whitespace and surrounding quotes. Brackets are *not* stripped
        // here — the bracketed-IPv6 regex below needs to see them so the
        // `[…](:port)?` form (RFC 7239 IPv6 in `Forwarded for=`, and some
        // proxies' XFF emission) gets the address extracted and the port
        // discarded before validation.
        $ip = trim($ip, " \t\n\r\0\x0B\"'");
        if ($ip === '') {
            return null;
        }

        // [IPv6](:port)? — extract the address between brackets; the optional
        // port is discarded.
        if (preg_match(self::BRACKETED_IPV6_PATTERN, $ip, $matches) === 1) {
            $ip = $matches[1];
        } elseif (preg_match('/^[0-9.]+:\\d+$/', $ip) === 1) {
            // IPv4:port — strip the port (IPv6 contains colons and is skipped here).
            $ip = explode(':', $ip, 2)[0];
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $binary = inet_pton($ip);
        if ($binary === false) {
            // filter_var() already accepted $ip as a valid IP; on the rare
            // platform where inet_pton still cannot parse it, fall back to the
            // validated text rather than dropping a usable address.
            return $ip;
        }

        // Collapse IPv4-mapped IPv6 ("::ffff:1.2.3.4", "::ffff:c000:0201") to
        // the embedded IPv4 form so downstream throttle / fail2ban / allow2ban
        // keys and event payloads see one representation per host. inet_ntop
        // then yields the canonical compressed form for genuine IPv6 addresses,
        // which keeps alt-forms (`2001:0db8::1` vs `2001:db8::1`, mixed case)
        // from fragmenting per-IP counters.
        $canonical = inet_ntop(CidrMatcher::canonicalizeBinary($binary));
        return $canonical === false ? null : $canonical;
    }
}
