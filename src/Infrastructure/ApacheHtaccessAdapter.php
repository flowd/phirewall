<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

use InvalidArgumentException;
use RuntimeException;

/**
 * Apache .htaccess adapter for IP blocking.
 *
 * This adapter maintains a managed section in the .htaccess file delimited by markers:
 *   # BEGIN Phirewall
 *   # END Phirewall
 *
 * Within this section, it writes "Require not ip <IP>" lines using mod_authz_core syntax
 * (Apache 2.4+). It preserves content outside the managed section.
 */
final readonly class ApacheHtaccessAdapter implements InfrastructureBlockerInterface
{
    private const BEGIN_MARK = '# BEGIN Phirewall';
    private const END_MARK   = '# END Phirewall';

    public function __construct(
        private string $htaccessPath,
    ) {
    }

    /**
     * Block a single IP address.
     */
    public function blockIp(string $ipAddress): void
    {
        $this->blockMany([$ipAddress]);
    }

    /**
     * Unblock a single IP address.
     */
    public function unblockIp(string $ipAddress): void
    {
        $this->unblockMany([$ipAddress]);
    }

    /**
     * Determine if a single IP is blocked.
     */
    public function isBlocked(string $ipAddress): bool
    {
        $ip = self::normalizeIp($ipAddress);
        [, $managed, ] = $this->readSections();
        $entries = self::parseManaged($managed);
        return in_array($ip, $entries, true);
    }

    /**
     * Block multiple IP addresses in a single atomic update.
     *
     * - Validates and normalizes all IPs first; if any is invalid, throws and does not modify the file.
     * - Idempotent: duplicate IPs are ignored; existing entries preserved; order remains stable.
     *
     * @param list<string> $ipAddresses
     */
    public function blockMany(array $ipAddresses): void
    {
        if ($ipAddresses === []) {
            return; // nothing to do
        }
        // Normalize all first to ensure all-or-nothing semantics
        $toAdd = [];
        foreach ($ipAddresses as $addr) {
            $toAdd[] = self::normalizeIp((string)$addr);
        }
        [$before, $managed, $after] = $this->readSections();
        $entries = self::parseManaged($managed);
        foreach ($toAdd as $ip) {
            if (!in_array($ip, $entries, true)) {
                $entries[] = $ip;
            }
        }
        $this->writeSections($before, $entries, $after);
    }

    /**
     * Unblock multiple IP addresses in a single atomic update.
     *
     * - Validates and normalizes all IPs first; if any is invalid, throws and does not modify the file.
     * - Idempotent: removing non-existent IPs is a no-op.
     *
     * @param list<string> $ipAddresses
     */
    public function unblockMany(array $ipAddresses): void
    {
        if ($ipAddresses === []) {
            return; // nothing to do
        }
        $toRemove = [];
        foreach ($ipAddresses as $addr) {
            $toRemove[] = self::normalizeIp((string)$addr);
        }
        [$before, $managed, $after] = $this->readSections();
        $current = self::parseManaged($managed);
        $removeSet = array_flip($toRemove);
        $entries = array_values(array_filter(
            $current,
            static fn(string $existing): bool => !isset($removeSet[$existing])
        ));
        $this->writeSections($before, $entries, $after);
    }

    private static function normalizeIp(string $ipAddress): string
    {
        $ipAddress = trim($ipAddress);
        if ('' === $ipAddress) {
            throw new InvalidArgumentException('IP address must not be empty');
        }

        $isV4 = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

        if (!$isV4 && !$isV6) {
            throw new InvalidArgumentException('Invalid IP address: ' . $ipAddress);
        }

        // For IPv6, ensure compressed canonical form to avoid duplicates in different forms
        if ($isV6) {
            $packed = @inet_pton($ipAddress);
            if ($packed === false) {
                throw new InvalidArgumentException('Invalid IPv6 address: ' . $ipAddress);
            }
            $normalized = inet_ntop($packed);
            if ($normalized === false) {
                throw new InvalidArgumentException('Invalid IPv6 address: ' . $ipAddress);
            }
            $ipAddress = $normalized;
        }
        return $ipAddress;
    }

    /**
     * @return array{0:string,1:string,2:string}
    */
    private function readSections(): array
    {
        $content = '';
        if (file_exists($this->htaccessPath)) {
            $content = (string) @file_get_contents($this->htaccessPath);
        }
        if ($content === '') {
            // No managed section yet
            return [$content, '', ''];
        }

        $beginPos = strpos($content, self::BEGIN_MARK);
        $endPos   = strpos($content, self::END_MARK);

        if ($beginPos === false || $endPos === false || $endPos < $beginPos) {
            // No managed section yet
            return [$content, '', ''];
        }

        $before = substr($content, 0, $beginPos);
        $managed = substr(
            $content,
            $beginPos + strlen(self::BEGIN_MARK),
            $endPos - ($beginPos + strlen(self::BEGIN_MARK))
        );
        $after = substr($content, $endPos + strlen(self::END_MARK));

        return [$before, $managed, $after];
    }

    /**
     * @param string $managedBody Content between markers (excluding markers)
     * @return list<string> list of IP addresses
     */
    private static function parseManaged(string $managedBody): array
    {
        $lines = preg_split('/\r?\n/', trim($managedBody)) ?: [];
        $entries = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            // Expect lines like: Require not ip 1.2.3.4
            if (preg_match('/^Require\s+not\s+ip\s+(.+)$/i', $line, $m) === 1) {
                $ip = trim($m[1]);
                if ($ip !== '') {
                    $entries[] = $ip;
                }
            }
        }
        // Keep unique and stable order
        $entries = array_values(array_unique($entries));
        return $entries;
    }

    /**
     * @param list<string> $entries
     */
    private function writeSections(string $before, array $entries, string $after): void
    {
        $managedBody = '';
        foreach ($entries as $ip) {
            $managedBody .= 'Require not ip ' . $ip . "\n";
        }
        $newContent = rtrim($before)
            . (rtrim($before) === '' ? '' : "\n\n")
            . self::BEGIN_MARK . "\n"
            . $managedBody
            . self::END_MARK
            . (rtrim($after) === '' ? "\n" : "\n\n")
            . ltrim($after);

        $dir = dirname($this->htaccessPath);
        if (!is_dir($dir)) {
            throw new RuntimeException('Directory does not exist: ' . $dir);
        }

        $tmp = $this->htaccessPath . '.tmp.' . bin2hex(random_bytes(6));
        $bytes = @file_put_contents($tmp, $newContent);
        if ($bytes === false) {
            throw new RuntimeException('Failed to write temp file: ' . $tmp);
        }

        // Try to preserve permissions if file exists
        if (file_exists($this->htaccessPath)) {
            @chmod($tmp, fileperms($this->htaccessPath) & 0777);
        }

        // Atomic replace
        if (!@rename($tmp, $this->htaccessPath)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to atomically replace htaccess file');
        }
    }
}
