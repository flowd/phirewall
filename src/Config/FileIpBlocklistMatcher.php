<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Request matcher that blocks when the client IP appears in a file-based list.
 *
 * Supports plain IPs (IPv4/IPv6) and CIDR ranges. The file is reloaded when its
 * modification time changes, so third-party generated lists can be swapped in
 * atomically (e.g., via rename) without restarting the process.
 */
final class FileIpBlocklistMatcher implements RequestMatcherInterface
{
    /** @var array<string, true> */
    private array $exactIps = [];

    /** @var list<array{network:string,bits:int}> */
    private array $cidrBlocks = [];

    private ?int $lastModified = null;

    /** @var callable(ServerRequestInterface):?string */
    private $ipResolver;

    public function __construct(
        private readonly string $filePath,
        ?callable $ipResolver = null,
    ) {
        $this->ipResolver = $ipResolver ?? static function (ServerRequestInterface $serverRequest): ?string {
            $params = $serverRequest->getServerParams();
            $ip = $params['REMOTE_ADDR'] ?? null;
            return is_string($ip) && $ip !== '' ? $ip : null;
        };
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $ipAddress = ($this->ipResolver)($serverRequest);
        if (!is_string($ipAddress) || $ipAddress === '') {
            return MatchResult::noMatch();
        }

        $this->reloadIfChanged();

        if (isset($this->exactIps[$ipAddress])) {
            return MatchResult::matched('ip_file_blocklist', ['ip' => $ipAddress]);
        }

        $ipBinary = @inet_pton($ipAddress);
        if ($ipBinary === false) {
            return MatchResult::noMatch();
        }

        foreach ($this->cidrBlocks as $cidrBlock) {
            if ($this->matchesCidr($ipBinary, $cidrBlock['network'], $cidrBlock['bits'])) {
                return MatchResult::matched('ip_file_blocklist', ['ip' => $ipAddress]);
            }
        }

        return MatchResult::noMatch();
    }

    private function reloadIfChanged(): void
    {
        clearstatcache(false, $this->filePath);
        $mtime = @filemtime($this->filePath);
        if ($mtime === false) {
            throw new \RuntimeException(sprintf('Blocklist file "%s" is not readable.', $this->filePath));
        }

        if ($this->lastModified !== null && $mtime === $this->lastModified) {
            return;
        }

        $content = @file_get_contents($this->filePath);
        if ($content === false) {
            throw new \RuntimeException(sprintf('Failed to read blocklist file "%s".', $this->filePath));
        }

        $this->lastModified = $mtime;
        $this->exactIps = [];
        $this->cidrBlocks = [];

        $lines = preg_split('/\r?\n/', $content) ?: [];
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

            if ($expiresAt !== null) {
                $now = time();
                if ($expiresAt <= $now) {
                    continue;
                }
            }

            if (str_contains($entry, '/')) {
                $this->addCidr($entry);
                continue;
            }

            if (filter_var($entry, FILTER_VALIDATE_IP) !== false) {
                $this->exactIps[$entry] = true;
            }
        }
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

    private function addCidr(string $cidr): void
    {
        [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $prefixLength = is_numeric($bits) ? (int)$bits : -1;
        $networkBinary = @inet_pton((string)$network);
        if ($networkBinary === false) {
            return;
        }

        $length = strlen($networkBinary);
        $maxBits = $length * 8;
        if ($prefixLength < 0 || $prefixLength > $maxBits) {
            return;
        }

        $this->cidrBlocks[] = [
            'network' => $networkBinary,
            'bits' => $prefixLength,
        ];
    }

    private function matchesCidr(string $ipBinary, string $networkBinary, int $prefixLength): bool
    {
        if (strlen($ipBinary) !== strlen($networkBinary)) {
            return false;
        }

        $fullBytes = intdiv($prefixLength, 8);
        $remainingBits = $prefixLength % 8;

        if ($fullBytes > 0 && strncmp($ipBinary, $networkBinary, $fullBytes) !== 0) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF00 >> $remainingBits) & 0xFF;
        $ipByte = ord($ipBinary[$fullBytes]) & $mask;
        $networkByte = ord($networkBinary[$fullBytes]) & $mask;

        return $ipByte === $networkByte;
    }
}
