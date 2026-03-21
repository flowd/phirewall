<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use PDO;
use PDOStatement;
use Psr\SimpleCache\CacheInterface;

/**
 * PDO-based cache backend for MySQL, PostgreSQL, or SQLite.
 *
 * Stores entries in a single table with columns: cache_key, cache_value, expires_at.
 * The table is auto-created on first use. All queries use prepared statements.
 * Identifiers (table and column names) are quoted using the appropriate dialect
 * (backticks for MySQL, double quotes for PostgreSQL/SQLite/ANSI SQL).
 *
 * Prepared statements are cached after first use to avoid repeated SQL parsing.
 *
 * Supports distributed counters when multiple servers share the same MySQL/PostgreSQL
 * database. SQLite is single-server only.
 *
 * For production use, consider indexing expires_at for efficient pruning.
 */
final class PdoCache implements CacheInterface, CounterStoreInterface
{
    private bool $tableCreated = false;

    private readonly string $driverName;

    /** Pre-quoted table name, safe for use in SQL statements. */
    private readonly string $table;

    /** Pre-quoted column names, safe for use in SQL statements. */
    private readonly string $colKey;

    private readonly string $colValue;

    private readonly string $colExpiresAt;

    /** @var array<string, PDOStatement> Cached prepared statements keyed by operation name. */
    private array $statements = [];

    public function __construct(
        private readonly PDO $pdo,
        string $tableName = 'phirewall_cache',
    ) {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->validateTableName($tableName);

        /** @var string $driverName */
        $driverName = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $this->driverName = $driverName;

        $this->table = $this->quoteIdentifier($tableName);
        $this->colKey = $this->quoteIdentifier('cache_key');
        $this->colValue = $this->quoteIdentifier('cache_value');
        $this->colExpiresAt = $this->quoteIdentifier('expires_at');
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->ensureTable();
        $this->maybePruneExpired();

        $stmt = $this->stmt('get', sprintf('SELECT %s, %s FROM %s WHERE %s = :key', $this->colValue, $this->colExpiresAt, $this->table, $this->colKey));
        $stmt->execute(['key' => $key]);
        /** @var array{cache_value: string, expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            return $default;
        }

        if ($row['expires_at'] !== null && (int) $row['expires_at'] <= time()) {
            $this->delete($key);
            return $default;
        }

        return unserialize($row['cache_value'], ['allowed_classes' => false]);
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->ensureTable();

        $expiresAt = $this->computeExpiresAt($ttl);
        $serialized = serialize($value);

        $this->upsert($key, $serialized, $expiresAt);

        return true;
    }

    public function delete(string $key): bool
    {
        $this->ensureTable();
        $stmt = $this->stmt('delete', sprintf('DELETE FROM %s WHERE %s = :key', $this->table, $this->colKey));
        $stmt->execute(['key' => $key]);
        return true;
    }

    public function clear(): bool
    {
        $this->ensureTable();
        $this->pdo->exec('DELETE FROM ' . $this->table);
        // Invalidate cached statements since table content is gone
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $this->ensureTable();
        $this->maybePruneExpired();

        $keyList = [];
        foreach ($keys as $key) {
            $keyList[] = $key;
        }

        if ($keyList === []) {
            return [];
        }

        // Dynamic placeholder count — cannot cache this statement
        $placeholders = implode(', ', array_fill(0, count($keyList), '?'));
        $stmt = $this->pdo->prepare(
            sprintf('SELECT %s, %s, %s FROM %s WHERE %s IN (%s)', $this->colKey, $this->colValue, $this->colExpiresAt, $this->table, $this->colKey, $placeholders)
        );
        $stmt->execute($keyList);
        /** @var list<array{cache_key: string, cache_value: string, expires_at: string|null}> $rows */
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $now = time();
        $found = [];
        foreach ($rows as $row) {
            if ($row['expires_at'] !== null && (int) $row['expires_at'] <= $now) {
                continue;
            }

            $found[$row['cache_key']] = unserialize($row['cache_value'], ['allowed_classes' => false]);
        }

        $result = [];
        foreach ($keyList as $key) {
            $result[$key] = $found[$key] ?? $default;
        }

        return $result;
    }

    /**
     * @param iterable<string|int, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $this->ensureTable();
        $expiresAt = $this->computeExpiresAt($ttl);

        $this->pdo->beginTransaction();
        try {
            foreach ($values as $key => $value) {
                $this->upsert((string) $key, serialize($value), $expiresAt);
            }

            $this->pdo->commit();
        } catch (\Throwable $throwable) {
            $this->pdo->rollBack();
            throw $throwable;
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $this->ensureTable();

        $keyList = [];
        foreach ($keys as $key) {
            $keyList[] = (string) $key;
        }

        if ($keyList === []) {
            return true;
        }

        // Dynamic placeholder count — cannot cache this statement
        $placeholders = implode(', ', array_fill(0, count($keyList), '?'));
        $stmt = $this->pdo->prepare(
            sprintf('DELETE FROM %s WHERE %s IN (%s)', $this->table, $this->colKey, $placeholders)
        );
        $stmt->execute($keyList);

        return true;
    }

    public function has(string $key): bool
    {
        $this->ensureTable();

        $stmt = $this->stmt('has', sprintf('SELECT %s FROM %s WHERE %s = :key', $this->colExpiresAt, $this->table, $this->colKey));
        $stmt->execute(['key' => $key]);
        /** @var array{expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            return false;
        }

        if ($row['expires_at'] !== null && (int) $row['expires_at'] <= time()) {
            return false;
        }

        return true;
    }

    /**
     * Atomically increment a counter within a fixed time window.
     *
     * Uses SELECT ... FOR UPDATE (MySQL/PostgreSQL) for row-level locking.
     * SQLite serializes all writers at the database level, so a regular
     * transaction is sufficient. The window is aligned to period boundaries
     * (e.g., period=60 aligns to the start of each minute).
     */
    public function increment(string $key, int $period): int
    {
        $this->ensureTable();

        $now = time();
        $windowStart = intdiv($now, $period) * $period;
        $windowEnd = $windowStart + $period;

        // SQLite serializes all writers at the database level, so a regular
        // transaction is sufficient. MySQL/PostgreSQL use SELECT ... FOR UPDATE
        // for row-level locking to prevent lost updates under concurrent access.
        $this->pdo->beginTransaction();

        try {
            $forUpdate = ($this->driverName !== 'sqlite') ? ' FOR UPDATE' : '';
            $stmtName = 'increment_select' . ($forUpdate !== '' ? '_lock' : '');
            $stmt = $this->stmt(
                $stmtName,
                sprintf('SELECT %s, %s FROM %s WHERE %s = :key%s', $this->colValue, $this->colExpiresAt, $this->table, $this->colKey, $forUpdate)
            );
            $stmt->execute(['key' => $key]);
            /** @var array{cache_value: string, expires_at: string|null}|false $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $currentValue = 0;
            if ($row !== false && ($row['expires_at'] === null || (int) $row['expires_at'] > $now)) {
                $currentValue = (int) $row['cache_value'];
            }

            $newValue = $currentValue + 1;

            $this->upsert($key, (string) $newValue, $windowEnd);
            $this->pdo->commit();

            return $newValue;
        } catch (\Throwable $throwable) {
            $this->pdo->rollBack();
            throw $throwable;
        }
    }

    public function ttlRemaining(string $key): int
    {
        $this->ensureTable();

        $stmt = $this->stmt('ttl', sprintf('SELECT %s FROM %s WHERE %s = :key', $this->colExpiresAt, $this->table, $this->colKey));
        $stmt->execute(['key' => $key]);
        /** @var array{expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false || $row['expires_at'] === null) {
            return 0;
        }

        $remaining = (int) $row['expires_at'] - time();
        return max(0, $remaining);
    }

    /**
     * Validate that the table name contains only safe characters.
     *
     * Prevents SQL injection through the table name. This is defense-in-depth:
     * identifiers are also quoted with driver-appropriate quote characters,
     * but validation ensures only expected characters are present.
     */
    private function validateTableName(string $tableName): void
    {
        if (preg_match('/^[a-zA-Z_]\w{0,63}$/', $tableName) !== 1) {
            throw new \InvalidArgumentException(
                'Table name must start with a letter or underscore, contain only alphanumeric '
                . 'characters and underscores, and be at most 64 characters long.'
            );
        }
    }

    /**
     * Quote an identifier (table or column name) using the appropriate dialect.
     *
     * MySQL uses backticks, PostgreSQL and SQLite use ANSI double quotes.
     */
    private function quoteIdentifier(string $identifier): string
    {
        if ($this->driverName === 'mysql') {
            return '`' . str_replace('`', '``', $identifier) . '`';
        }

        // ANSI SQL standard: double quotes (PostgreSQL, SQLite, and others)
        return '"' . str_replace('"', '""', $identifier) . '"';
    }

    /**
     * Get or create a cached prepared statement.
     *
     * Statements are cached by operation name to avoid re-parsing the same SQL
     * on every call. This is the hot path for increment() which runs 2 queries.
     */
    private function stmt(string $name, string $sql): PDOStatement
    {
        return $this->statements[$name] ??= $this->pdo->prepare($sql);
    }

    private function ensureTable(): void
    {
        if ($this->tableCreated) {
            return;
        }

        $this->pdo->exec(
            sprintf('CREATE TABLE IF NOT EXISTS %s (', $this->table)
            . ($this->colKey . ' VARCHAR(255) NOT NULL PRIMARY KEY, ')
            . ($this->colValue . ' TEXT NOT NULL, ')
            . ($this->colExpiresAt . ' INTEGER NULL')
            . ')'
        );
        $this->tableCreated = true;
    }

    /**
     * Insert or update a cache entry using the appropriate SQL dialect.
     */
    private function upsert(string $key, string $serializedValue, ?int $expiresAt): void
    {
        $cols = sprintf('(%s, %s, %s)', $this->colKey, $this->colValue, $this->colExpiresAt);

        $sql = match ($this->driverName) {
            'sqlite' => sprintf('INSERT OR REPLACE INTO %s %s VALUES (:key, :value, :expires_at)', $this->table, $cols),
            'pgsql' => sprintf('INSERT INTO %s %s VALUES (:key, :value, :expires_at) ', $this->table, $cols)
                . sprintf('ON CONFLICT (%s) DO UPDATE SET %s = EXCLUDED.%s, ', $this->colKey, $this->colValue, $this->colValue)
                . sprintf('%s = EXCLUDED.%s', $this->colExpiresAt, $this->colExpiresAt),
            default => sprintf('INSERT INTO %s %s VALUES (:key, :value, :expires_at) ', $this->table, $cols)
                . sprintf('ON DUPLICATE KEY UPDATE %s = VALUES(%s), ', $this->colValue, $this->colValue)
                . sprintf('%s = VALUES(%s)', $this->colExpiresAt, $this->colExpiresAt),
        };

        $stmt = $this->stmt('upsert', $sql);
        $stmt->execute([
            'key' => $key,
            'value' => $serializedValue,
            'expires_at' => $expiresAt,
        ]);
    }

    private function computeExpiresAt(null|int|DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }

        if ($ttl instanceof DateInterval) {
            return (new \DateTimeImmutable())->add($ttl)->getTimestamp();
        }

        return time() + $ttl;
    }

    /**
     * Probabilistically prune expired entries to keep the table size in check.
     *
     * Runs roughly 1% of the time on read operations.
     */
    private function maybePruneExpired(): void
    {
        if (random_int(1, 100) > 1) {
            return;
        }

        $stmt = $this->stmt('prune', sprintf('DELETE FROM %s WHERE %s IS NOT NULL AND %s <= :now', $this->table, $this->colExpiresAt, $this->colExpiresAt));
        $stmt->execute(['now' => time()]);
    }
}
