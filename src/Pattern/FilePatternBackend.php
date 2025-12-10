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
        $handle = @fopen($this->filePath, 'cb+');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Cannot open pattern file "%s" for writing.', $this->filePath));
        }

        $now = ($this->now)();

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException(sprintf('Cannot lock pattern file "%s".', $this->filePath));
            }

            [$entries, $order] = $this->readEntriesRaw($handle, $now);
            $key = $this->entryKey($patternEntry);
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
                $merged = $this->mergeEntry($existing, $incoming);
                if ($merged !== $existing) {
                    $entries[$key] = $merged;
                    $changed = true;
                }
            }

            if ($changed) {
                if (count($entries) > self::MAX_ENTRIES) {
                    throw new \RuntimeException(sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES));
                }

                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, $this->formatEntries($entries, $order));
                fflush($handle);
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function pruneExpired(): void
    {
        $this->ensureDirectory();
        $handle = @fopen($this->filePath, 'cb+');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Cannot open pattern file "%s" for writing.', $this->filePath));
        }

        $now = ($this->now)();

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException(sprintf('Cannot lock pattern file "%s".', $this->filePath));
            }

            [$entries, $order] = $this->readEntriesRaw($handle, $now, pruneExpired: true);
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $this->formatEntries($entries, $order));
            fflush($handle);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function type(): string
    {
        return 'file';
    }

    public function capabilities(): array
    {
        return [
            'kinds' => PatternKind::all(),
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

            $key = $this->entryKey($entry);
            if (!array_key_exists($key, $entries)) {
                $order[] = $key;
                $entries[$key] = $entry;
                continue;
            }

            $merged = $this->mergeEntry($entries[$key], $entry);
            $entries[$key] = $merged;
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

        if (!in_array($kind, PatternKind::all(), true)) {
            return null;
        }

        $expiresAt = ctype_digit($expiresRaw) ? (int) $expiresRaw : null;
        $addedAt = ctype_digit($addedRaw) ? (int) $addedRaw : null;

        return new PatternEntry(
            kind: $kind,
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
            $patternEntry->kind,
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

    private function entryKey(PatternEntry $patternEntry): string
    {
        return $patternEntry->kind . ':' . $patternEntry->target . ':' . $patternEntry->value;
    }

    private function mergeEntry(PatternEntry $existing, PatternEntry $incoming): PatternEntry
    {

        $expiresAt = max($existing->expiresAt ?? 0, $incoming->expiresAt ?? 0);

        $addedAt = $existing->addedAt;
        if ($incoming->addedAt !== null && ($existing->addedAt === null || $incoming->addedAt > $existing->addedAt)) {
            $addedAt = $incoming->addedAt;
        }

        return new PatternEntry(
            kind: $existing->kind,
            value: $existing->value,
            target: $existing->target,
            expiresAt: $expiresAt,
            addedAt: $addedAt,
            metadata: $existing->metadata,
        );
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

        if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
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
