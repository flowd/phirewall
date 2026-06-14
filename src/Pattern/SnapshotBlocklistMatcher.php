<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use Psr\Http\Message\ServerRequestInterface;

final class SnapshotBlocklistMatcher implements RequestMatcherInterface
{
    private ?PatternSnapshot $patternSnapshot = null;

    /**
     * @var array<string, array<string, mixed>>
     */
    private array $compiled = [];

    /** @var callable(ServerRequestInterface): ?string */
    private $ipExtractor;

    public function __construct(
        private readonly PatternBackendInterface $patternBackend,
        ?callable $ipResolver = null,
        private readonly string $backendName = '',
    ) {
        $this->ipExtractor = $ipResolver ?? KeyExtractors::ip();
    }

    /**
     * Name of the pattern backend this matcher reads from, as registered on the
     * Config. Empty when built from a bare backend instance with no registered
     * name. {@see \Flowd\Phirewall\Config::with()} uses it to re-point the
     * matcher at the winning backend when layers override a backend by name.
     */
    public function backendName(): string
    {
        return $this->backendName;
    }

    /**
     * Return an equivalent matcher reading from a different backend instance,
     * preserving the IP resolver and backend name. Lets composition apply a
     * later layer's backend override to rules carried over from earlier layers.
     * Returns $this unchanged when the backend is already identical.
     */
    public function withBackend(PatternBackendInterface $patternBackend): self
    {
        if ($patternBackend === $this->patternBackend) {
            return $this;
        }

        return new self($patternBackend, $this->ipExtractor, $this->backendName);
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $patternSnapshot = $this->loadSnapshot();
        $ip = ($this->ipExtractor)($serverRequest);
        $path = $serverRequest->getUri()->getPath();
        $query = $serverRequest->getUri()->getQuery();

        // Pre-compute binary IP once (used by CIDR matching)
        $ipBinary = ($ip !== null) ? @inet_pton($ip) : false;

        // Collapse IPv4-mapped IPv6 peers (`::ffff:x.x.x.x`) once so a client
        // presented in that form by a dual-stack host still matches IPv4 entries.
        $canonicalIp = ($ip !== null) ? CidrMatcher::canonicalizeIp($ip) : null;

        foreach ($patternSnapshot->entries as $entry) {
            $compiled = $this->compiled[$entry->kind->value][$this->entryKey($entry)] ?? null;
            if ($compiled === null) {
                continue;
            }

            switch ($entry->kind) {
                case PatternKind::IP:
                    // $compiled is the entry's canonical IP, pre-computed in compileEntry().
                    if ($canonicalIp !== null && $canonicalIp === $compiled) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::CIDR:
                    /** @var array{network: string, bits: int}|null $cidrCompiled */
                    $cidrCompiled = is_array($compiled) ? $compiled : null;
                    if ($ipBinary !== false && $cidrCompiled !== null && CidrMatcher::matches($ipBinary, $cidrCompiled)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_EXACT:
                    if ($path === $entry->value) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_PREFIX:
                    if (str_starts_with($path, $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_REGEX:
                    $pathPattern = is_string($compiled) ? $compiled : null;
                    if (RegexMatcher::matches($pathPattern, $path)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::HEADER_EXACT:
                    // PSR-7 getHeader() is case-insensitive, so look up only the
                    // target header instead of normalizing the whole header map.
                    $headerName = $entry->target ?? '';
                    if ($headerName !== '' && $this->headerValuesEqual($serverRequest->getHeader($headerName), $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::HEADER_REGEX:
                    $headerName = $entry->target ?? '';
                    $headerPattern = is_string($compiled) ? $compiled : null;
                    if ($headerName !== '' && $this->headerValuesMatch($serverRequest->getHeader($headerName), $headerPattern)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::REQUEST_REGEX:
                    // Only REQUEST_REGEX needs the full normalized header map; build
                    // it lazily once, and only when such an entry is actually present.
                    $normalizedHeaders ??= $this->normalizeHeaders($serverRequest->getHeaders());
                    $requestSubject ??= $this->buildRequestSubject($path, $query, $normalizedHeaders);
                    $requestPattern = is_string($compiled) ? $compiled : null;
                    if (RegexMatcher::matches($requestPattern, $requestSubject)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
            }
        }

        return MatchResult::noMatch();
    }

    private function loadSnapshot(): PatternSnapshot
    {
        // consume() runs on every request; version equality gates recompilation so
        // the compiled matchers are only rebuilt when the backend actually changed.
        $freshSnapshot = $this->patternBackend->consume();
        if (!$this->patternSnapshot instanceof PatternSnapshot || $freshSnapshot->version !== $this->patternSnapshot->version) {
            $this->patternSnapshot = $freshSnapshot;
            $this->compiled = $this->compileSnapshot($freshSnapshot);
        }

        return $freshSnapshot;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function compileSnapshot(PatternSnapshot $patternSnapshot): array
    {
        $compiled = [];
        $count = 0;
        foreach ($patternSnapshot->entries as $entry) {
            ++$count;
            if ($count > PatternBackendInterface::MAX_ENTRIES_DEFAULT) {
                break;
            }

            $key = $this->entryKey($entry);
            $compiled[$entry->kind->value][$key] = $this->compileEntry($entry);
        }

        return $compiled;
    }

    private function compileEntry(PatternEntry $patternEntry): mixed
    {
        return match ($patternEntry->kind) {
            PatternKind::CIDR => CidrMatcher::compile($patternEntry->value),
            // Canonicalise IP entries once at compile time so match() compares
            // against a pre-computed key instead of re-running inet_pton/inet_ntop
            // for every entry on every request (mirrors IpMatcher's keying).
            PatternKind::IP => CidrMatcher::canonicalizeIp($patternEntry->value),
            PatternKind::PATH_REGEX, PatternKind::HEADER_REGEX, PatternKind::REQUEST_REGEX => RegexMatcher::compile($patternEntry->value),
            default => $patternEntry->value,
        };
    }

    /**
     * Entry key with case-insensitive target for header matching.
     */
    private function entryKey(PatternEntry $patternEntry): string
    {
        $target = $patternEntry->target !== null ? strtolower($patternEntry->target) : '';
        return $patternEntry->kind->value . ':' . $target . ':' . $patternEntry->value;
    }

    /**
     * @param array<string> $values Header values as returned by PSR-7 getHeader().
     */
    private function headerValuesEqual(array $values, string $expected): bool
    {
        return in_array($expected, $values, true);
    }

    /**
     * @param array<string> $values Header values as returned by PSR-7 getHeader().
     */
    private function headerValuesMatch(array $values, ?string $pattern): bool
    {
        if ($pattern === null) {
            return false;
        }

        foreach ($values as $value) {
            if (RegexMatcher::matches($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, array<int, string>> $headers
     * @return array<string, array<int, string>>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $values) {
            $normalized[strtolower($name)] = $values;
        }

        return $normalized;
    }

    /**
     * @param array<string, array<int,string>> $headers
     */
    private function buildRequestSubject(string $path, string $query, array $headers): string
    {
        $subject = $query === '' ? $path : $path . '?' . $query;
        $headerParts = [];
        foreach ($headers as $name => $values) {
            foreach ($values as $value) {
                $headerParts[] = $name . ':' . $value;
            }
        }

        if ($headerParts !== []) {
            $subject .= "\n" . implode("\n", $headerParts);
        }

        return $subject;
    }
}
