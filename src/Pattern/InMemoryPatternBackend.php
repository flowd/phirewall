<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

/**
 * In-memory pattern backend for configuring blocklists without file I/O.
 *
 * Useful for:
 * - Hardcoded CIDR ranges or IPs
 * - Configuration-based blocklists
 * - Testing
 *
 * Example:
 *   $backend = new InMemoryPatternBackend([
 *       new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
 *       new PatternEntry(PatternKind::IP, '192.168.1.100'),
 *   ]);
 *   $config->blocklists->addPatternBackend('internal', $backend);
 *   $config->blocklists->fromBackend('block-internal', 'internal');
 */
final class InMemoryPatternBackend implements PatternBackendInterface
{
    private const MAX_ENTRIES = self::MAX_ENTRIES_DEFAULT;

    /** @var array<string, PatternEntry> */
    private array $entries = [];

    /** @var list<string> */
    private array $order = [];

    private int $version = 0;

    /** @var callable():int */
    private $now;

    /**
     * @param list<PatternEntry> $initialEntries
     */
    public function __construct(array $initialEntries = [], ?callable $now = null)
    {
        $this->now = $now ?? static fn(): int => time();

        foreach ($initialEntries as $initialEntry) {
            $this->appendInternal($initialEntry);
        }
    }

    public function consume(): PatternSnapshot
    {
        $now = ($this->now)();
        $entries = [];

        foreach ($this->order as $key) {
            if (!isset($this->entries[$key])) {
                continue;
            }

            $entry = $this->entries[$key];

            // Skip expired entries
            if ($entry->expiresAt !== null && $entry->expiresAt <= $now) {
                continue;
            }

            $entries[] = $entry;
        }

        return new PatternSnapshot($entries, $this->version, 'memory');
    }

    public function append(PatternEntry $patternEntry): void
    {
        $this->appendInternal($patternEntry);
        ++$this->version;
    }

    public function pruneExpired(): void
    {
        $now = ($this->now)();
        $expiredKeys = [];

        foreach ($this->entries as $key => $entry) {
            if ($entry->expiresAt !== null && $entry->expiresAt <= $now) {
                $expiredKeys[$key] = true;
                unset($this->entries[$key]);
            }
        }

        if ($expiredKeys !== []) {
            $this->order = array_values(array_filter(
                $this->order,
                static fn(string $k): bool => !isset($expiredKeys[$k]),
            ));
            ++$this->version;
        }
    }

    public function type(): string
    {
        return 'memory';
    }

    public function capabilities(): array
    {
        return [
            'kinds' => PatternKind::all(),
            'max_entries' => self::MAX_ENTRIES,
        ];
    }

    /**
     * Remove all entries.
     */
    public function clear(): void
    {
        $this->entries = [];
        $this->order = [];
        ++$this->version;
    }

    /**
     * Get the current number of entries.
     */
    public function count(): int
    {
        return count($this->entries);
    }

    private function appendInternal(PatternEntry $patternEntry): void
    {
        $now = ($this->now)();
        $key = $this->entryKey($patternEntry);
        $existing = $this->entries[$key] ?? null;

        $incoming = new PatternEntry(
            kind: $patternEntry->kind,
            value: $patternEntry->value,
            target: $patternEntry->target,
            expiresAt: $patternEntry->expiresAt,
            addedAt: $patternEntry->addedAt ?? $now,
            metadata: $patternEntry->metadata,
        );

        if ($existing === null) {
            if (count($this->entries) >= self::MAX_ENTRIES) {
                throw new \RuntimeException(sprintf('InMemoryPatternBackend exceeds maximum entries (%d).', self::MAX_ENTRIES));
            }

            $this->entries[$key] = $incoming;
            $this->order[] = $key;
        } else {
            $this->entries[$key] = $this->mergeEntry($existing, $incoming);
        }
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
            expiresAt: $expiresAt ?: null,
            addedAt: $addedAt,
            metadata: $existing->metadata,
        );
    }
}
