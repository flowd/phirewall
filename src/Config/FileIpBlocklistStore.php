<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

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

        $handle = @fopen($this->filePath, 'cb+');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Cannot open blocklist file "%s" for writing.', $this->filePath));
        }

        $now = ($this->now)();

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException(sprintf('Cannot lock blocklist file "%s".', $this->filePath));
            }

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
                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, $this->formatEntries($entries, $order));
                fflush($handle);
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
            flock($handle, LOCK_UN);
            fclose($handle);
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

    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);
        if ($dir === '' || $dir === '.' || is_dir($dir)) {
            return;
        }

        if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Failed to create directory for blocklist file "%s".', $this->filePath));
        }
    }
}
