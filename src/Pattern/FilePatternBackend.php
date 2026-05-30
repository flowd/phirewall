<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

final class FilePatternBackend implements PatternBackendInterface
{
    private const DELIMITER = '|';

    private const COMMENT_PREFIXES = ['#', ';'];

    private const MAX_ENTRIES = self::MAX_ENTRIES_DEFAULT;

    /** @var callable():int */
    private $now;

    public function __construct(private readonly string $filePath, ?callable $now = null)
    {
        $this->now = $now ?? static fn(): int => time();
    }

    public function consume(): PatternSnapshot
    {
        $this->ensureDirectory();
        $this->ensureFileExists();

        clearstatcache(false, $this->filePath);
        $mtime = @filemtime($this->filePath);
        if ($mtime === false) {
            throw new \RuntimeException(sprintf('Pattern file "%s" is not readable.', $this->filePath));
        }

        $entries = $this->readEntries();

        return new PatternSnapshot($entries, $mtime, $this->filePath);
    }

    public function append(PatternEntry $patternEntry): void
    {
        $this->ensureDirectory();

        $lockHandle = $this->acquireLock();
        $now = ($this->now)();

        try {
            $handle = @fopen($this->filePath, 'cb+');
            if ($handle === false) {
                throw new \RuntimeException(sprintf('Cannot open pattern file "%s" for writing.', $this->filePath));
            }

            try {
                [$entries, $order] = $this->readEntriesRaw($handle, $now);
                $key = $patternEntry->key();
                $existing = $entries[$key] ?? null;

                $incoming = new PatternEntry(
                    kind: $patternEntry->kind,
                    value: $patternEntry->value,
                    target: $patternEntry->target,
                    expiresAt: $patternEntry->expiresAt,
                    addedAt: $patternEntry->addedAt ?? $now,
                    metadata: $patternEntry->metadata,
                );

                $changed = false;
                if ($existing === null) {
                    $entries[$key] = $incoming;
                    $order[] = $key;
                    $changed = true;
                } else {
                    $merged = $existing->merge($incoming);
                    if ($merged->expiresAt !== $existing->expiresAt || $merged->addedAt !== $existing->addedAt) {
                        $entries[$key] = $merged;
                        $changed = true;
                    }
                }

                if ($changed) {
                    if (count($entries) > self::MAX_ENTRIES) {
                        throw new \RuntimeException(sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES));
                    }

                    $this->atomicWrite($this->formatEntries($entries, $order));
                }
            } finally {
                fclose($handle);
            }
        } finally {
            $this->releaseLock($lockHandle);
        }
    }

    public function pruneExpired(): void
    {
        $this->ensureDirectory();

        $lockHandle = $this->acquireLock();
        $now = ($this->now)();

        try {
            $handle = @fopen($this->filePath, 'cb+');
            if ($handle === false) {
                throw new \RuntimeException(sprintf('Cannot open pattern file "%s" for writing.', $this->filePath));
            }

            try {
                [$entries, $order] = $this->readEntriesRaw($handle, $now, pruneExpired: true);
                $this->atomicWrite($this->formatEntries($entries, $order));
            } finally {
                fclose($handle);
            }
        } finally {
            $this->releaseLock($lockHandle);
        }
    }

    /**
     * Write `$content` to the pattern file via a temp file + atomic rename so
     * a mid-write crash cannot leave the live file empty. Callers must hold the
     * sidecar lock from acquireLock() while calling this: the rename swaps the
     * live file's inode, so a lock held on the live file itself would not
     * serialize a writer already blocked on the now-orphaned inode, letting it
     * resume against stale content and clobber the just-completed update.
     */
    private function atomicWrite(string $content): void
    {
        $temp = $this->filePath . '.tmp.' . bin2hex(random_bytes(6));
        $bytes = @file_put_contents($temp, $content);
        if ($bytes === false) {
            throw new \RuntimeException(sprintf('Failed to write temp pattern file "%s".', $temp));
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
            throw new \RuntimeException(sprintf('Failed to atomically replace pattern file "%s".', $this->filePath));
        }
    }

    /**
     * Acquire an exclusive lock used to serialize writers.
     *
     * The lock lives on a dedicated, never-renamed sidecar file (`<path>.lock`)
     * instead of on the live pattern file, because atomicWrite() replaces the
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
            throw new \RuntimeException(sprintf('Cannot lock pattern lock file "%s".', $lockPath));
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

    public function type(): string
    {
        return 'file';
    }

    public function capabilities(): array
    {
        return [
            'kinds' => PatternKind::cases(),
            'max_entries' => self::MAX_ENTRIES,
        ];
    }

    /**
     * @return list<PatternEntry>
     */
    private function readEntries(): array
    {
        $handle = @fopen($this->filePath, 'rb');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Cannot open pattern file "%s" for reading.', $this->filePath));
        }

        $now = ($this->now)();
        try {
            [$entries] = $this->readEntriesRaw($handle, $now, pruneExpired: false);
        } finally {
            fclose($handle);
        }

        if (count($entries) > self::MAX_ENTRIES) {
            throw new \RuntimeException(sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES));
        }

        return array_values($entries);
    }

    /**
     * @param resource $handle
     * @return array{array<string,PatternEntry>, list<string>}
     */
    private function readEntriesRaw($handle, int $now, bool $pruneExpired = false): array
    {
        rewind($handle);
        $contents = stream_get_contents($handle);
        if ($contents === false) {
            return [[], []];
        }

        $lines = preg_split('/\r?\n/', $contents) ?: [];
        $entries = [];
        $order = [];

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }

            if ($this->isComment($trimmed)) {
                continue;
            }

            $entry = $this->parseLine($trimmed);
            if (!$entry instanceof \Flowd\Phirewall\Pattern\PatternEntry) {
                continue;
            }

            if ($entry->expiresAt !== null && $entry->expiresAt <= $now) {
                if (!$pruneExpired) {
                    continue;
                }

                // Skip to prune
                continue;
            }

            $key = $entry->key();
            if (!array_key_exists($key, $entries)) {
                $order[] = $key;
                $entries[$key] = $entry;
                continue;
            }

            $entries[$key] = $entries[$key]->merge($entry);
        }

        return [$entries, $order];
    }

    private function parseLine(string $line): ?PatternEntry
    {
        $parts = $this->splitFields($line);
        $kind = trim($parts[0] ?? '');
        $value = trim($parts[1] ?? '');
        $target = trim($parts[2] ?? '');
        $expiresRaw = trim($parts[3] ?? '');
        $addedRaw = trim($parts[4] ?? '');

        if ($kind === '') {
            return null;
        }

        if ($value === '') {
            return null;
        }

        $patternKind = PatternKind::tryFrom($kind);
        if (!$patternKind instanceof \Flowd\Phirewall\Pattern\PatternKind) {
            return null;
        }

        $expiresAt = ctype_digit($expiresRaw) ? (int) $expiresRaw : null;
        $addedAt = ctype_digit($addedRaw) ? (int) $addedRaw : null;

        return new PatternEntry(
            kind: $patternKind,
            value: $this->decodeField($value),
            target: $target !== '' ? $this->decodeField($target) : null,
            expiresAt: $expiresAt,
            addedAt: $addedAt,
        );
    }

    /**
     * @param array<string,PatternEntry> $entries
     * @param list<string> $order
     */
    private function formatEntries(array $entries, array $order): string
    {
        $lines = [];
        foreach ($order as $key) {
            if (!isset($entries[$key])) {
                continue;
            }

            $entry = $entries[$key];
            $lines[] = $this->formatLine($entry);
        }

        return $lines === [] ? '' : implode("\n", $lines) . "\n";
    }

    private function formatLine(PatternEntry $patternEntry): string
    {
        $parts = [
            $patternEntry->kind->value,
            $this->encodeField($patternEntry->value),
            $patternEntry->target !== null ? $this->encodeField($patternEntry->target) : '',
            $patternEntry->expiresAt !== null ? (string) $patternEntry->expiresAt : '',
            $patternEntry->addedAt !== null ? (string) $patternEntry->addedAt : '',
        ];

        return implode(self::DELIMITER, $parts);
    }

    /**
     * Split a line by the delimiter while honoring backslash escapes.
     *
     * @return list<string>
     */
    private function splitFields(string $line): array
    {
        $fields = [];
        $current = '';
        $escaped = false;

        $length = strlen($line);
        for ($i = 0; $i < $length; ++$i) {
            $char = $line[$i];
            if ($escaped) {
                $current .= $char;
                $escaped = false;
                continue;
            }

            if ($char === '\\') {
                $escaped = true;
                continue;
            }

            if ($char === self::DELIMITER) {
                $fields[] = $current;
                $current = '';
                continue;
            }

            $current .= $char;
        }

        $fields[] = $current;

        return $fields;
    }

    private function encodeField(string $value): string
    {
        return str_replace(['\\', self::DELIMITER], ['\\\\', '\\' . self::DELIMITER], $value);
    }

    private function decodeField(string $value): string
    {
        return str_replace(['\\' . self::DELIMITER, '\\\\'], [self::DELIMITER, '\\'], $value);
    }

    private function isComment(string $line): bool
    {
        foreach (self::COMMENT_PREFIXES as $prefix) {
            if (str_starts_with($line, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);
        if ($dir === '' || $dir === '.' || is_dir($dir)) {
            return;
        }

        // 0700: pattern files contain blocklist data; the directory should not
        // be readable by other local users on the host.
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Failed to create directory for pattern file "%s".', $this->filePath));
        }
    }

    private function ensureFileExists(): void
    {
        if (is_file($this->filePath)) {
            return;
        }

        $this->ensureDirectory();
        $handle = @fopen($this->filePath, 'cb');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Cannot create pattern file "%s".', $this->filePath));
        }

        fclose($handle);
    }
}
