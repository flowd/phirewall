<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches requests by client IP against a list of IPs and CIDR ranges.
 *
 * Supports both IPv4 and IPv6 addresses and CIDR notation.
 * Used internally by SafelistSection::ip() and BlocklistSection::ip().
 */
final class IpMatcher implements RequestMatcherInterface
{
    /** @var list<array{network: string, bits: int}> */
    private array $compiled = [];

    /** @var array<string, bool> */
    private array $exactIps = [];

    /** @var callable(ServerRequestInterface): ?string */
    private $ipResolver;

    /**
     * @param list<string> $ipsOrCidrs List of IPs and/or CIDR ranges (e.g. '10.0.0.1', '192.168.0.0/16', '::1')
     * @param (callable(ServerRequestInterface): ?string)|null $ipResolver Custom IP resolver. Defaults to KeyExtractors::ip().
     */
    public function __construct(array $ipsOrCidrs, ?callable $ipResolver = null)
    {
        $this->ipResolver = $ipResolver ?? KeyExtractors::ip();
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
                    $this->exactIps[$binary] = true;
                }
            }
        }
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $ip = ($this->ipResolver)($serverRequest);
        if ($ip === null) {
            return MatchResult::noMatch();
        }

        $ipBinary = @inet_pton($ip);
        if ($ipBinary === false) {
            return MatchResult::noMatch();
        }

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
