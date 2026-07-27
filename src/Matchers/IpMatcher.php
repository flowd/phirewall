<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Flowd\Phirewall\Support\CompiledDataCache;
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
 *
 * The entries are compiled into binary lookup tables on the first match, not
 * at construction. With a compiled-data cache on the evaluating Config
 * ({@see CompiledDataCacheAware}) the tables load from a compiled artifact
 * keyed by the content hash of the entry list, so large lists (threat feeds)
 * skip the per-request compilation entirely. Unparseable entries are skipped,
 * as before; only non-string entries throw, still at construction.
 */
final class IpMatcher implements RequestMatcherInterface, ClientIpResolverAware, CompiledDataCacheAware
{
    /**
     * Format version of the compiled lookup tables. The compiled-cache
     * identifier is keyed on the entry content alone (no source files), so
     * bump this whenever {@see compileTables()} or {@see CidrMatcher} changes
     * the table shape, to force existing artifacts to rebuild after an upgrade.
     */
    private const COMPILED_SCHEMA_VERSION = 1;

    /** @var list<string>|null Entries awaiting compilation; null once compiled. */
    private ?array $pendingEntries;

    /** @var list<array{network: string, bits: int}> */
    private array $compiled = [];

    /** @var array<string, bool> */
    private array $exactIps = [];

    private ?CompiledDataCache $compiledDataCache = null;

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
        }

        $this->pendingEntries = array_values($ipsOrCidrs);
    }

    public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
    {
        $this->compiledDataCache = $compiledDataCache;
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
        $this->ensureCompiled();

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

    /**
     * Compile the pending entries into the lookup tables on first use, served
     * from the compiled-data cache when one was injected.
     */
    private function ensureCompiled(): void
    {
        if ($this->pendingEntries === null) {
            return;
        }

        $entries = $this->pendingEntries;
        $this->pendingEntries = null;

        if ($this->compiledDataCache instanceof CompiledDataCache) {
            // Content-addressed identifier: a changed list gets a fresh
            // artifact, so no source files need watching.
            $identifier = 'ip-matcher-v' . self::COMPILED_SCHEMA_VERSION . '-' . sha1(implode("\n", $entries));
            $tables = $this->compiledDataCache->load($identifier, [], static fn(): array => self::compileTables($entries));
        } else {
            $tables = self::compileTables($entries);
        }

        $cidrs = $tables['cidrs'] ?? [];
        $exact = $tables['exact'] ?? [];
        if (is_array($cidrs) && is_array($exact)) {
            /** @var list<array{network: string, bits: int}> $cidrs */
            /** @var array<string, bool> $exact */
            $this->compiled = $cidrs;
            $this->exactIps = $exact;
        }
    }

    /**
     * @param list<string> $entries
     * @return array{cidrs: list<array{network: string, bits: int}>, exact: array<string, bool>}
     */
    private static function compileTables(array $entries): array
    {
        $cidrs = [];
        $exact = [];
        foreach ($entries as $entry) {
            if (str_contains($entry, '/')) {
                $compiled = CidrMatcher::compile($entry);
                if ($compiled !== null) {
                    $cidrs[] = $compiled;
                }

                continue;
            }

            $binary = @inet_pton($entry);
            if ($binary !== false) {
                // Canonicalize the stored key the same way lookups are
                // canonicalized, so a rule written in IPv4-mapped IPv6 form
                // (`::ffff:x.x.x.x`) still matches a plain-IPv4 peer.
                $exact[CidrMatcher::canonicalizeBinary($binary)] = true;
            }
        }

        return ['cidrs' => $cidrs, 'exact' => $exact];
    }
}
