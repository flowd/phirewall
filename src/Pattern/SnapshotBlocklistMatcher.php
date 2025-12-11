<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

final class SnapshotBlocklistMatcher implements RequestMatcherInterface, PatternFrontendInterface
{
    private const MAX_REGEX_LENGTH = 4096;

    private const MAX_SUBJECT_LENGTH = 8192;

    private ?PatternSnapshot $patternSnapshot = null;

    /**
     * @var array<string, array<string, mixed>>
     */
    private array $compiled = [];

    public function __construct(private readonly PatternBackendInterface $patternBackend)
    {
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $patternSnapshot = $this->loadSnapshot();
        $ip = $this->extractIp($serverRequest);
        $path = $serverRequest->getUri()->getPath();
        $query = $serverRequest->getUri()->getQuery();
        $headers = $this->normalizeHeaders($serverRequest->getHeaders());

        foreach ($patternSnapshot->entries as $entry) {
            $compiled = $this->compiled[$entry->kind][$this->entryKey($entry)] ?? null;
            if ($compiled === null) {
                continue;
            }

            switch ($entry->kind) {
                case PatternKind::IP:
                    if ($ip !== null && $ip === $entry->value) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::CIDR:
                    /** @var array{network: string, bits: int}|null $cidrCompiled */
                    $cidrCompiled = is_array($compiled) ? $compiled : null;
                    if ($ip !== null && $this->matchesCidr($ip, $cidrCompiled)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_EXACT:
                    if ($path === $entry->value) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_PREFIX:
                    if (str_starts_with($path, $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_REGEX:
                    $pathPattern = is_string($compiled) ? $compiled : null;
                    if ($this->regexMatch($pathPattern, $path)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::HEADER_EXACT:
                    $headerName = $entry->target ?? '';
                    if ($headerName !== '' && $this->headerEquals($headers, $headerName, $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::HEADER_REGEX:
                    $headerName = $entry->target ?? '';
                    $headerPattern = is_string($compiled) ? $compiled : null;
                    if ($headerName !== '' && $this->headerRegex($headers, $headerName, $headerPattern)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::REQUEST_REGEX:
                    $subject = $this->buildRequestSubject($path, $query, $headers);
                    $requestPattern = is_string($compiled) ? $compiled : null;
                    if ($this->regexMatch($requestPattern, $subject)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind, 'value' => $entry->value]);
                    }

                    break;
            }
        }

        return MatchResult::noMatch();
    }

    private function loadSnapshot(): PatternSnapshot
    {
        $patternSnapshot = $this->patternBackend->consume();
        if (!$this->patternSnapshot instanceof \Flowd\Phirewall\Pattern\PatternSnapshot || $patternSnapshot->version !== $this->patternSnapshot->version) {
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
            $compiled[$entry->kind][$key] = $this->compileEntry($entry);
        }

        return $compiled;
    }

    private function compileEntry(PatternEntry $patternEntry): mixed
    {
        return match ($patternEntry->kind) {
            PatternKind::CIDR => $this->compileCidr($patternEntry->value),
            PatternKind::PATH_REGEX, PatternKind::HEADER_REGEX, PatternKind::REQUEST_REGEX => $this->compileRegex($patternEntry->value),
            default => $patternEntry->value,
        };
    }

    private function entryKey(PatternEntry $patternEntry): string
    {
        $target = $patternEntry->target !== null ? strtolower($patternEntry->target) : '';
        return $patternEntry->kind . ':' . $target . ':' . $patternEntry->value;
    }

    /**
     * @return array{network: string, bits: int}|null
     */
    private function compileCidr(string $cidr): ?array
    {
        [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $prefixLength = is_numeric($bits) ? (int) $bits : -1;
        $networkBinary = @inet_pton((string) $network);
        if ($networkBinary === false) {
            return null;
        }

        $length = strlen($networkBinary);
        $maxBits = $length * 8;
        if ($prefixLength < 0 || $prefixLength > $maxBits) {
            return null;
        }

        return ['network' => $networkBinary, 'bits' => $prefixLength];
    }

    /**
     * @param array{network: string, bits: int}|null $compiled
     */
    private function matchesCidr(string $ipAddress, ?array $compiled): bool
    {
        if ($compiled === null) {
            return false;
        }

        $ipBinary = @inet_pton($ipAddress);
        if ($ipBinary === false) {
            return false;
        }

        if (strlen($ipBinary) !== strlen($compiled['network'])) {
            return false;
        }

        $fullBytes = intdiv($compiled['bits'], 8);
        $remainingBits = $compiled['bits'] % 8;

        if ($fullBytes > 0 && strncmp($ipBinary, $compiled['network'], $fullBytes) !== 0) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF00 >> $remainingBits) & 0xFF;
        $ipByte = ord($ipBinary[$fullBytes]) & $mask;
        $networkByte = ord($compiled['network'][$fullBytes]) & $mask;

        return $ipByte === $networkByte;
    }

    private function compileRegex(string $pattern): ?string
    {
        if (strlen($pattern) > self::MAX_REGEX_LENGTH) {
            return null;
        }

        set_error_handler(static fn(): bool => true);
        try {
            $result = @preg_match($pattern, '');
            if ($result === false) {
                return null;
            }
        } finally {
            restore_error_handler();
        }

        return $pattern;
    }

    private function regexMatch(?string $pattern, string $subject): bool
    {
        if ($pattern === null) {
            return false;
        }

        if (strlen($subject) > self::MAX_SUBJECT_LENGTH) {
            $subject = substr($subject, 0, self::MAX_SUBJECT_LENGTH);
        }

        set_error_handler(static fn(): bool => true);
        try {
            $result = @preg_match($pattern, $subject);
            return $result === 1;
        } finally {
            restore_error_handler();
        }
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
            if ($this->regexMatch($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize header array to lower-case keys for case-insensitive lookup.
     *
     * @param array<string, array<int, string>> $headers
     * @return array<string, array<int, string>>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $values) {
            $normalizedName = strtolower($name);
            $normalized[$normalizedName] = $values;
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
            $subject .= '\n' . implode('\n', $headerParts);
        }

        return $subject;
    }

    private function extractIp(ServerRequestInterface $serverRequest): ?string
    {
        $params = $serverRequest->getServerParams();
        $ip = $params['REMOTE_ADDR'] ?? null;
        return is_string($ip) && $ip !== '' ? $ip : null;
    }
}
