<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use Psr\Http\Message\ServerRequestInterface;

final class SnapshotBlocklistMatcher implements RequestMatcherInterface, PatternFrontendInterface
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
    ) {
        $this->ipExtractor = $ipResolver ?? KeyExtractors::ip();
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $patternSnapshot = $this->loadSnapshot();
        $ip = ($this->ipExtractor)($serverRequest);
        $path = $serverRequest->getUri()->getPath();
        $query = $serverRequest->getUri()->getQuery();

        // Pre-compute binary IP once (used by CIDR matching)
        $ipBinary = ($ip !== null) ? @inet_pton($ip) : false;

        foreach ($patternSnapshot->entries as $entry) {
            $compiled = $this->compiled[$entry->kind->value][$this->entryKey($entry)] ?? null;
            if ($compiled === null) {
                continue;
            }

            switch ($entry->kind) {
                case PatternKind::IP:
                    if ($ip !== null && $ip === $entry->value) {
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
                    $headers ??= $this->normalizeHeaders($serverRequest->getHeaders());
                    $headerName = $entry->target ?? '';
                    if ($headerName !== '' && $this->headerEquals($headers, $headerName, $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::HEADER_REGEX:
                    $headers ??= $this->normalizeHeaders($serverRequest->getHeaders());
                    $headerName = $entry->target ?? '';
                    $headerPattern = is_string($compiled) ? $compiled : null;
                    if ($headerName !== '' && $this->headerRegex($headers, $headerName, $headerPattern)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::REQUEST_REGEX:
                    $headers ??= $this->normalizeHeaders($serverRequest->getHeaders());
                    $requestSubject ??= $this->buildRequestSubject($path, $query, $headers);
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
        $patternSnapshot = $this->patternBackend->consume();
        if (!$this->patternSnapshot instanceof PatternSnapshot || $patternSnapshot->version !== $this->patternSnapshot->version) {
            $this->patternSnapshot = $patternSnapshot;
            $this->compiled = $this->compileSnapshot($patternSnapshot);
        }

        return $patternSnapshot;
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
     * @param array<string, array<int,string>> $headers
     */
    private function headerEquals(array $headers, string $name, string $expected): bool
    {
        $normalizedName = strtolower($name);
        if (!isset($headers[$normalizedName])) {
            return false;
        }

        foreach ($headers[$normalizedName] as $value) {
            if ($value === $expected) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, array<int,string>> $headers
     */
    private function headerRegex(array $headers, string $name, ?string $pattern): bool
    {
        if ($pattern === null) {
            return false;
        }

        $normalizedName = strtolower($name);
        if (!isset($headers[$normalizedName])) {
            return false;
        }

        foreach ($headers[$normalizedName] as $value) {
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
