<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches requests by client IP against a list of IPs and CIDR ranges.
 *
 * Supports both IPv4 and IPv6 addresses and CIDR notation.
 * Used internally by SafelistSection::ip() and BlocklistSection::ip().
 *
 * When constructed without an explicit resolver the client IP is read through
 * the evaluating Config's resolver at match time ({@see ClientIpResolverAware});
 * standalone use falls back to the raw REMOTE_ADDR peer address.
 */
final class IpMatcher implements RequestMatcherInterface, ClientIpResolverAware
{
    /** @var list<array{network: string, bits: int}> */
    private array $compiled = [];

    /** @var array<string, bool> */
    private array $exactIps = [];

    /** @var (callable(ServerRequestInterface): ?string)|null */
    private $ipResolver;

    /**
     * @param list<string> $ipsOrCidrs List of IPs and/or CIDR ranges (e.g. '10.0.0.1', '192.168.0.0/16', '::1')
     * @param (callable(ServerRequestInterface): ?string)|null $ipResolver Explicit IP resolver. When omitted, the evaluating Config's resolver is used (falling back to REMOTE_ADDR).
     */
    public function __construct(array $ipsOrCidrs, ?callable $ipResolver = null)
    {
        $this->ipResolver = $ipResolver;
        foreach ($ipsOrCidrs as $i => $ipOrCidr) {
            if (!is_string($ipOrCidr)) {
                throw new \InvalidArgumentException(sprintf('IP/CIDR entry at index %d must be a string.', $i));
            }

            if (str_contains($ipOrCidr, '/')) {
                $compiled = CidrMatcher::compile($ipOrCidr);
                if ($compiled !== null) {
                    $this->compiled[] = $compiled;
                }
            } else {
                $binary = @inet_pton($ipOrCidr);
                if ($binary !== false) {
                    // Canonicalize the stored key the same way lookups are
                    // canonicalized, so a rule written in IPv4-mapped IPv6 form
                    // (`::ffff:x.x.x.x`) still matches a plain-IPv4 peer.
                    $this->exactIps[CidrMatcher::canonicalizeBinary($binary)] = true;
                }
            }
        }
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        return $this->matchWithResolver($serverRequest, static function (ServerRequestInterface $serverRequest): ?string {
            $remoteAddr = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;
            return is_string($remoteAddr) && $remoteAddr !== '' ? $remoteAddr : null;
        });
    }

    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult
    {
        $resolver = $this->ipResolver ?? $defaultResolver;
        $ip = $resolver($serverRequest);
        if ($ip === null) {
            return MatchResult::noMatch();
        }

        $ipBinary = @inet_pton($ip);
        if ($ipBinary === false) {
            return MatchResult::noMatch();
        }

        // Dual-stack hosts often present IPv4 clients via the IPv4-mapped IPv6
        // form (`::ffff:x.x.x.x`). Collapse to the embedded 4-byte IPv4 binary
        // before lookup so rules written in IPv4 notation match either
        // presentation.
        $ipBinary = CidrMatcher::canonicalizeBinary($ipBinary);

        if (isset($this->exactIps[$ipBinary])) {
            return MatchResult::matched('ip_match', ['ip' => $ip]);
        }

        foreach ($this->compiled as $cidr) {
            if (CidrMatcher::matches($ipBinary, $cidr)) {
                return MatchResult::matched('ip_match', ['ip' => $ip]);
            }
        }

        return MatchResult::noMatch();
    }
}
