<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Flowd\Phirewall\Matchers\ClientIpResolverAware;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Request matcher that blocks when the client IP appears in a file-based list.
 *
 * Supports plain IPs (IPv4/IPv6) and CIDR ranges. The file is reloaded when its
 * modification time changes, so third-party generated lists can be swapped in
 * atomically (e.g., via rename) without restarting the process.
 *
 * To avoid blocking I/O on every request and to reduce DoS risk from transient
 * filesystem issues, reload attempts are throttled by a minimal reload interval
 * and the matcher keeps using the last known good state if a reload fails.
 */
final class FileIpBlocklistMatcher implements RequestMatcherInterface, ClientIpResolverAware
{
    /** @var array<string, true> */
    private array $exactIps = [];

    /** @var list<array{network:string,bits:int}> */
    private array $cidrBlocks = [];

    private ?int $lastModified = null;

    private ?int $lastReloadAttempt = null;

    /**
     * @param (callable(ServerRequestInterface): ?string)|null $ipResolver
     *                                                                     How to extract the client IP from a request. When omitted
     *                                                                     ({@see ClientIpResolverAware}), the matcher late-binds to the
     *                                                                     resolver of the {@see \Flowd\Phirewall\Config} it is evaluated
     *                                                                     under, falling back to `REMOTE_ADDR` (the raw peer address,
     *                                                                     no proxy headers) when used standalone or when that
     *                                                                     Config sets none. Deployments behind a CDN, load balancer, or
     *                                                                     reverse proxy must configure a trusted client-IP resolver - set
     *                                                                     it on the Config via `setIpResolver((new TrustedProxyResolver([...]))->resolve(...))`,
     *                                                                     or pass one explicitly here as `(new TrustedProxyResolver([...]))->resolve(...)`
     *                                                                     - otherwise every request appears to come from the proxy's
     *                                                                     address and the blocklist will either fail to match real
     *                                                                     attackers or end up banning the proxy itself. An explicitly
     *                                                                     passed resolver always wins over the Config's.
     */
    public function __construct(
        private readonly string $filePath,
        ?callable $ipResolver = null,
        private readonly int $minReloadIntervalSec = 1,
    ) {
        if ($this->minReloadIntervalSec < 0) {
            throw new \InvalidArgumentException('minReloadIntervalSec must be >= 0');
        }

        $this->ipResolver = $ipResolver;
    }

    /** @var (callable(ServerRequestInterface):?string)|null */
    private $ipResolver;

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
        $ipAddress = $resolver($serverRequest);
        if (!is_string($ipAddress) || $ipAddress === '') {
            return MatchResult::noMatch();
        }

        $this->reloadIfChanged();

        // Collapse IPv4-mapped IPv6 peers (`::ffff:x.x.x.x`) so a client
        // presented in that form by a dual-stack host still matches IPv4 entries.
        if (isset($this->exactIps[CidrMatcher::canonicalizeIp($ipAddress)])) {
            return MatchResult::matched('ip_file_blocklist', ['ip' => $ipAddress]);
        }

        $ipBinary = @inet_pton($ipAddress);
        if ($ipBinary === false) {
            return MatchResult::noMatch();
        }

        foreach ($this->cidrBlocks as $cidrBlock) {
            if (CidrMatcher::matches($ipBinary, $cidrBlock)) {
                return MatchResult::matched('ip_file_blocklist', ['ip' => $ipAddress]);
            }
        }

        return MatchResult::noMatch();
    }

    private function reloadIfChanged(): void
    {
        $now = time();
        if ($this->minReloadIntervalSec > 0 && $this->lastReloadAttempt !== null && ($now - $this->lastReloadAttempt) < $this->minReloadIntervalSec) {
            return;
        }

        $this->lastReloadAttempt = $now;

        clearstatcache(false, $this->filePath);
        $mtime = @filemtime($this->filePath);
        if ($mtime === false) {
            // On first load we must fail hard to avoid using an undefined state.
            if ($this->lastModified === null) {
                throw new \RuntimeException(sprintf('Blocklist file "%s" is not readable.', $this->filePath));
            }

            // For subsequent reloads, keep using the last known good state.
            return;
        }

        if ($this->lastModified !== null && $mtime === $this->lastModified) {
            return;
        }

        $content = @file_get_contents($this->filePath);
        if ($content === false) {
            if ($this->lastModified === null) {
                throw new \RuntimeException(sprintf('Failed to read blocklist file "%s".', $this->filePath));
            }

            // Keep using last known good state on transient read failures.
            return;
        }

        $lines = preg_split('/\r?\n/', $content) ?: [];
        $exactIps = [];
        $cidrBlocks = [];
        $parseNow = $now;

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }

            if (str_starts_with($trimmed, '#')) {
                continue;
            }

            if (str_starts_with($trimmed, ';')) {
                continue;
            }

            [$entry, $expiresAt] = $this->parseEntry($trimmed);
            if ($entry === null) {
                continue;
            }

            if ($expiresAt !== null && $expiresAt <= $parseNow) {
                continue;
            }

            if (str_contains($entry, '/')) {
                $this->addCidrToList($cidrBlocks, $entry);
                continue;
            }

            if (filter_var($entry, FILTER_VALIDATE_IP) !== false) {
                $exactIps[CidrMatcher::canonicalizeIp($entry)] = true;
            }
        }

        // Only swap state after successful parse.
        $this->lastModified = $mtime;
        $this->exactIps = $exactIps;
        $this->cidrBlocks = $cidrBlocks;
    }

    /**
     * @return array{string|null,int|null}
     */
    private function parseEntry(string $line): array
    {
        [$entry, $expiresRaw] = array_pad(explode('|', $line, 3), 3, null);
        $entry = trim((string)$entry);
        if ($entry === '') {
            return [null, null];
        }

        $expiresAt = null;
        if ($expiresRaw !== null) {
            $expiresRaw = trim((string) $expiresRaw);
            if ($expiresRaw !== '' && ctype_digit($expiresRaw)) {
                $expiresAt = (int)$expiresRaw;
            }
        }

        return [$entry, $expiresAt];
    }

    /**
     * @param list<array{network:string,bits:int}> $target
     */
    private function addCidrToList(array &$target, string $cidr): void
    {
        $compiled = CidrMatcher::compile($cidr);
        if ($compiled !== null) {
            $target[] = $compiled;
        }
    }
}
