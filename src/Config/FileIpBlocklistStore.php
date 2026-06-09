<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Flowd\Phirewall\Matchers\Support\CidrMatcher;

/**
 * Minimal file-backed list manager for IP blocklists.
 *
 * - Supports concurrent writers via flock.
 * - Writes are idempotent (no duplicate lines) and safe for atomic list swaps.
 * - File format: one entry per line, comments allowed with # or ;
 */
final class FileIpBlocklistStore
{
    /** @var callable():int */
    private $now;

    public function __construct(private readonly string $filePath, ?callable $now = null)
    {
        $this->now = $now ?? static fn(): int => time();
    }

    /** @param list<string> $ipsOrCidrs */
    public function addAll(array $ipsOrCidrs): void
    {
        $this->addAllInternal($ipsOrCidrs, null);
    }

    /** @param list<string> $ipsOrCidrs */
    public function addAllWithTtl(array $ipsOrCidrs, int $ttlSeconds): void
    {
        if ($ttlSeconds <= 0) {
            throw new \InvalidArgumentException('TTL seconds must be positive.');
        }

        $this->addAllInternal($ipsOrCidrs, $ttlSeconds);
    }

    public function add(string $ipOrCidr): void
    {
        $this->addAll([$ipOrCidr]);
    }

    public function addWithTtl(string $ipOrCidr, int $ttlSeconds): void
    {
        $this->addAllWithTtl([$ipOrCidr], $ttlSeconds);
    }

    /** Remove expired entries without adding new ones. */
    public function pruneExpired(): void
    {
        $this->addAllInternal([], null);
    }

    public function getFilePath(): string
    {
        return $this->filePath;
    }

    /**
     * @param list<string> $ipsOrCidrs
     */
    private function addAllInternal(array $ipsOrCidrs, ?int $ttlSeconds): void
    {
        if ($ipsOrCidrs === [] && $ttlSeconds !== null) {
            return;
        }

        $this->ensureDirectory();

        $lockHandle = $this->acquireLock();
        $now = ($this->now)();

        try {
            $handle = @fopen($this->filePath, 'cb+');
            if ($handle === false) {
                throw new \RuntimeException(sprintf('Cannot open blocklist file "%s" for writing.', $this->filePath));
            }

            try {
                $expiredPruned = false;
                $lastAddedAt = null;
                [$entries, $order, $lastAddedAt] = $this->readEntries($handle, $now, $expiredPruned);

                $needsRewrite = $expiredPruned;
                $changedEntries = [];
                foreach ($ipsOrCidrs as $entry) {
                    $entry = trim($entry);
                    if ($entry === '') {
                        continue;
                    }

                    if (str_starts_with($entry, '#')) {
                        continue;
                    }

                    if (str_starts_with($entry, ';')) {
                        continue;
                    }

                    // Only persist well-formed IPs/CIDRs. This also rejects values carrying a
                    // newline, which would otherwise be split into a second (injected) entry on read.
                    if (!$this->isValidIpOrCidr($entry)) {
                        continue;
                    }

                    $expiresAt = $ttlSeconds === null ? null : $now + $ttlSeconds;
                    if (!array_key_exists($entry, $entries)) {
                        $entries[$entry] = ['expiresAt' => $expiresAt, 'addedAt' => $now];
                        $order[] = $entry;
                        $needsRewrite = true;
                        $changedEntries[$entry] = $entries[$entry];
                        continue;
                    }

                    $existing = $entries[$entry];
                    $updated = $this->mergeEntry($existing, $expiresAt, $now);
                    if ($updated !== $existing) {
                        $entries[$entry] = $updated;
                        $needsRewrite = true;
                        $changedEntries[$entry] = $updated;
                    }
                }

                $effectiveLastAddedAt = $lastAddedAt;
                if ($changedEntries !== []) {
                    $effectiveLastAddedAt = max($effectiveLastAddedAt ?? $now, $now);
                }

                $canRewrite = $effectiveLastAddedAt === null || ($now - $effectiveLastAddedAt) >= 60;

                if ($needsRewrite && $canRewrite) {
                    $this->atomicWrite($this->formatEntries($entries, $order));
                } elseif ($changedEntries !== []) {
                    // Append-only update when rewrite throttle is active
                    fseek($handle, 0, SEEK_END);
                    foreach ($changedEntries as $entry => $meta) {
                        $line = $this->formatEntryLine($entry, $meta['expiresAt'], $meta['addedAt']);
                        fwrite($handle, $line . "\n");
                    }

                    fflush($handle);
                }
            } finally {
                fclose($handle);
            }
        } finally {
            $this->releaseLock($lockHandle);
        }
    }

    /**
     * @param resource $handle
     * @return array{array<string,array{expiresAt: ?int, addedAt: ?int}>, list<string>, ?int}
     */
    private function readEntries($handle, int $now, bool &$expiredPruned): array
    {
        rewind($handle);
        $contents = stream_get_contents($handle);
        if ($contents === false) {
            return [[], [], null];
        }

        $lines = preg_split('/\r?\n/', $contents) ?: [];
        $entries = [];
        $order = [];
        $expiredPruned = false;
        $lastAddedAt = null;

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

            [$entry, $expiresAt, $addedAt] = $this->parseEntry($trimmed);
            if ($entry === null) {
                continue;
            }

            if ($expiresAt !== null && $expiresAt <= $now) {
                $expiredPruned = true;
                continue;
            }

            if (!array_key_exists($entry, $entries)) {
                $order[] = $entry;
            }

            $entries[$entry] = $this->mergeEntry($entries[$entry] ?? ['expiresAt' => null, 'addedAt' => $addedAt], $expiresAt, $addedAt ?? $now);
            if ($addedAt !== null) {
                $lastAddedAt = max($lastAddedAt ?? $addedAt, $addedAt);
            }
        }

        return [$entries, $order, $lastAddedAt];
    }

    /**
     * @param array{expiresAt: ?int,addedAt: ?int} $existing
     * @return array{expiresAt: ?int,addedAt: ?int}
     */
    private function mergeEntry(array $existing, ?int $incomingExpiresAt, int $incomingAddedAt): array
    {
        $expiresAt = $existing['expiresAt'];
        $expiresAt = $expiresAt === null || $incomingExpiresAt === null ? null : max($expiresAt, $incomingExpiresAt);

        $addedAt = $existing['addedAt'];
        if ($addedAt === null || $incomingAddedAt > $addedAt) {
            $addedAt = $incomingAddedAt;
        }

        return ['expiresAt' => $expiresAt, 'addedAt' => $addedAt];
    }

    /** Whether the entry is a plain IP or a CIDR range, mirroring the matcher's read-side parse. */
    private function isValidIpOrCidr(string $entry): bool
    {
        if (str_contains($entry, '/')) {
            return CidrMatcher::compile($entry) !== null;
        }

        return filter_var($entry, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * @return array{string|null, int|null, int|null}
     */
    private function parseEntry(string $line): array
    {
        [$entry, $expiresRaw, $addedRaw] = array_pad(explode('|', $line, 3), 3, null);
        $entry = trim((string)$entry);
        if ($entry === '') {
            return [null, null, null];
        }

        $expiresAt = null;
        if ($expiresRaw !== null) {
            $expiresRaw = trim((string) $expiresRaw);
            if ($expiresRaw !== '' && ctype_digit($expiresRaw)) {
                $expiresAt = (int)$expiresRaw;
            }
        }

        $addedAt = null;
        if ($addedRaw !== null) {
            $addedRaw = trim((string) $addedRaw);
            if ($addedRaw !== '' && ctype_digit($addedRaw)) {
                $addedAt = (int)$addedRaw;
            }
        }

        return [$entry, $expiresAt, $addedAt];
    }

    /**
     * @param array<string,array{expiresAt: ?int,addedAt: ?int}> $entries
     * @param list<string> $order
     */
    private function formatEntries(array $entries, array $order): string
    {
        $lines = [];
        foreach ($order as $entry) {
            $meta = $entries[$entry] ?? ['expiresAt' => null, 'addedAt' => null];
            $lines[] = $this->formatEntryLine($entry, $meta['expiresAt'], $meta['addedAt']);
        }

        return $lines === [] ? '' : implode("\n", $lines) . "\n";
    }

    private function formatEntryLine(string $entry, ?int $expiresAt, ?int $addedAt): string
    {
        if ($expiresAt === null && $addedAt === null) {
            return $entry;
        }

        if ($addedAt === null) {
            return $entry . '|' . $expiresAt;
        }

        if ($expiresAt === null) {
            return $entry . '||' . $addedAt;
        }

        return $entry . '|' . $expiresAt . '|' . $addedAt;
    }

    /**
     * Write `$content` to the blocklist file via a temp file + atomic rename
     * so a mid-write crash cannot leave the live file empty. Only used on
     * the full-rewrite path; the append-only path stays in-place because a
     * partial line at end-of-file is tolerated by the parser and the next
     * write reconciles the contents. Callers must hold the sidecar lock from
     * acquireLock() so the inode swap performed by rename() cannot strand a
     * concurrent writer on the orphaned inode.
     */
    private function atomicWrite(string $content): void
    {
        $temp = $this->filePath . '.tmp.' . bin2hex(random_bytes(6));
        $bytes = @file_put_contents($temp, $content);
        if ($bytes === false) {
            throw new \RuntimeException(sprintf('Failed to write temp blocklist file "%s".', $temp));
        }

        // Match the live file's mode (falling back to owner-only) so the rename
        // never widens a pre-existing restrictive permission set.
        $mode = 0600;
        if (is_file($this->filePath)) {
            $perms = @fileperms($this->filePath);
            if ($perms !== false) {
                $mode = $perms & 0777;
            }
        }

        @chmod($temp, $mode);

        if (!@rename($temp, $this->filePath)) {
            @unlink($temp);
            throw new \RuntimeException(sprintf('Failed to atomically replace blocklist file "%s".', $this->filePath));
        }
    }

    /**
     * Acquire an exclusive lock used to serialize writers.
     *
     * The lock lives on a dedicated, never-renamed sidecar file (`<path>.lock`)
     * instead of on the live blocklist file, because atomicWrite() replaces the
     * latter via rename(). A lock held on the live file would be stranded on the
     * orphaned inode after a rename and would no longer serialize concurrent
     * writers.
     *
     * @return resource
     */
    private function acquireLock()
    {
        $lockPath = $this->filePath . '.lock';
        $lockHandle = @fopen($lockPath, 'cb');
        if ($lockHandle === false) {
            throw new \RuntimeException(sprintf('Cannot open lock file "%s".', $lockPath));
        }

        if (!flock($lockHandle, LOCK_EX)) {
            fclose($lockHandle);
            throw new \RuntimeException(sprintf('Cannot lock blocklist lock file "%s".', $lockPath));
        }

        return $lockHandle;
    }

    /**
     * @param resource $lockHandle
     */
    private function releaseLock($lockHandle): void
    {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }

    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);
        if ($dir === '' || $dir === '.' || is_dir($dir)) {
            return;
        }

        // 0700: blocklist directory should not be readable by other local
        // users on the host.
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Failed to create directory for blocklist file "%s".', $this->filePath));
        }
    }
}
