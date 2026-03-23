<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use PDO;
use PDOStatement;
use Psr\SimpleCache\CacheInterface;

/**
 * PDO-based cache backend for MySQL, PostgreSQL, and SQLite.
 *
 * Stores entries in a single table with columns: cache_key, cache_value, expires_at.
 * The table is auto-created on first use when the database user has CREATE TABLE
 * privileges; otherwise create it manually (see ensureTable() for the DDL).
 *
 * All data queries use prepared statements. Identifiers are quoted with the
 * appropriate dialect character (backticks for MySQL, double quotes for others).
 *
 * For production use, consider adding an index on expires_at for efficient pruning.
 */
final class PdoCache implements CacheInterface, CounterStoreInterface
{
    private const SUPPORTED_DRIVERS = ['sqlite', 'mysql', 'pgsql'];

    private bool $tableCreated = false;

    /** @var 'sqlite'|'mysql'|'pgsql' */
    private readonly string $driverName;

    /** @var array<string, PDOStatement> Cached prepared statements keyed by operation name. */
    private array $statements = [];

    private readonly QuotedIdentifier $quotedTable;

    private readonly string $quoteChar;

    public function __construct(
        private readonly PDO $pdo,
        string $tableName = 'phirewall_cache',
    ) {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->validateTableName($tableName);

        $driverName = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        if (!is_string($driverName) || !in_array($driverName, self::SUPPORTED_DRIVERS, true)) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Unsupported PDO driver "%s". Supported: %s.',
                    is_string($driverName) ? $driverName : 'unknown',
                    implode(', ', self::SUPPORTED_DRIVERS),
                )
            );
        }

        /** @var 'sqlite'|'mysql'|'pgsql' $driverName */
        $this->driverName = $driverName;
        $this->quoteChar = $driverName === 'mysql' ? '`' : '"';
        $this->quotedTable = QuotedIdentifier::quote($tableName, $this->quoteChar);
    }

    // ── CacheInterface ──────────────────────────────────────────────────

    public function get(string $key, mixed $default = null): mixed
    {
        $this->ensureTable();
        $this->maybePruneExpired();

        $stmt = $this->stmt(
            'get',
            "SELECT {$this->quoteColumn('cache_value')}, {$this->quoteColumn('expires_at')}"
            . " FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} = :key",
        );
        $stmt->execute(['key' => $key]);

        /** @var array{cache_value: string, expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        if ($row === false) {
            return $default;
        }

        if ($row['expires_at'] !== null && (int) $row['expires_at'] <= time()) {
            $this->delete($key);
            return $default;
        }

        return json_decode($row['cache_value'], true, 512, JSON_THROW_ON_ERROR);
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->ensureTable();

        $expiresAt = $this->computeExpiresAt($ttl);

        if ($expiresAt !== null && $expiresAt <= time()) {
            return $this->delete($key);
        }

        $this->upsert($key, json_encode($value, JSON_THROW_ON_ERROR), $expiresAt);

        return true;
    }

    public function delete(string $key): bool
    {
        $this->ensureTable();

        $stmt = $this->stmt(
            'delete',
            "DELETE FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} = :key",
        );
        $stmt->execute(['key' => $key]);

        return true;
    }

    public function clear(): bool
    {
        $this->ensureTable();
        $this->pdo->exec("DELETE FROM {$this->quotedTable}");

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $this->ensureTable();
        $this->maybePruneExpired();

        $keyList = [];
        foreach ($keys as $key) {
            $keyList[] = (string) $key;
        }

        if ($keyList === []) {
            return [];
        }

        $placeholders = implode(', ', array_fill(0, count($keyList), '?'));
        $stmt = $this->pdo->prepare(
            "SELECT {$this->quoteColumn('cache_key')}, {$this->quoteColumn('cache_value')}, {$this->quoteColumn('expires_at')}"
            . " FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} IN ({$placeholders})",
        );
        $stmt->execute($keyList);

        /** @var list<array{cache_key: string, cache_value: string, expires_at: string|null}> $rows */
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        $now = time();
        $found = [];
        $expiredKeys = [];
        foreach ($rows as $row) {
            if ($row['expires_at'] !== null && (int) $row['expires_at'] <= $now) {
                $expiredKeys[] = $row['cache_key'];
                continue;
            }

            $found[$row['cache_key']] = json_decode($row['cache_value'], true, 512, JSON_THROW_ON_ERROR);
        }

        if ($expiredKeys !== []) {
            $this->deleteMultiple($expiredKeys);
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
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
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

        $placeholders = implode(', ', array_fill(0, count($keyList), '?'));
        $stmt = $this->pdo->prepare(
            "DELETE FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} IN ({$placeholders})",
        );
        $stmt->execute($keyList);

        return true;
    }

    public function has(string $key): bool
    {
        $this->ensureTable();
        $this->maybePruneExpired();

        $stmt = $this->stmt(
            'has',
            "SELECT {$this->quoteColumn('expires_at')} FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} = :key",
        );
        $stmt->execute(['key' => $key]);

        /** @var array{expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        if ($row === false) {
            return false;
        }

        if ($row['expires_at'] !== null && (int) $row['expires_at'] <= time()) {
            $this->delete($key);
            return false;
        }

        return true;
    }

    // ── CounterStoreInterface ───────────────────────────────────────────

    /**
     * Atomically increment a counter within a fixed time window.
     *
     * The window is aligned to period boundaries (e.g., period=60 aligns to
     * the start of each minute). Expired entries reset to 1. Since increment()
     * is the only writer for counter keys, the stored value is always numeric.
     *
     * MySQL lacks RETURNING support so it uses a transaction with a separate
     * SELECT. PostgreSQL and SQLite use a single upsert with RETURNING.
     */
    public function increment(string $key, int $period): int
    {
        if ($period < 1) {
            throw new \InvalidArgumentException(
                sprintf('Period must be at least 1, got %d.', $period),
            );
        }

        $this->ensureTable();
        $this->maybePruneExpired();

        $now = time();
        $windowStart = intdiv($now, $period) * $period;
        $windowEnd = $windowStart + $period;

        if ($this->driverName === 'mysql') {
            return $this->incrementWithTransaction($key, $windowEnd, $now);
        }

        return $this->incrementWithReturning($key, $windowEnd, $now);
    }

    public function ttlRemaining(string $key): int
    {
        $this->ensureTable();

        $stmt = $this->stmt(
            'ttl',
            "SELECT {$this->quoteColumn('expires_at')} FROM {$this->quotedTable} WHERE {$this->quoteColumn('cache_key')} = :key",
        );
        $stmt->execute(['key' => $key]);

        /** @var array{expires_at: string|null}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        if ($row === false || $row['expires_at'] === null) {
            return 0;
        }

        return max(0, (int) $row['expires_at'] - time());
    }

    // ── Increment strategies ────────────────────────────────────────────

    /**
     * PostgreSQL and SQLite: single atomic upsert with RETURNING.
     *
     * Both databases support ON CONFLICT ... DO UPDATE ... RETURNING.
     * SQLite requires 3.35+ (PHP 8.1+ ships 3.36+).
     */
    private function incrementWithReturning(string $key, int $windowEnd, int $now): int
    {
        $colKey = $this->quoteColumn('cache_key');
        $colValue = $this->quoteColumn('cache_value');
        $colExpiry = $this->quoteColumn('expires_at');

        $table = $this->quotedTable;

        $sql = "INSERT INTO {$table} ({$colKey}, {$colValue}, {$colExpiry})"
            . " VALUES (:key, '1', :expires_at)"
            . " ON CONFLICT ({$colKey}) DO UPDATE SET"
            . " {$colValue} = CASE"
            . " WHEN {$table}.{$colExpiry} IS NOT NULL AND {$table}.{$colExpiry} <= :now THEN '1'"
            . ($this->driverName === 'pgsql'
                ? " ELSE ({$table}.{$colValue}::int + 1)::text END,"
                : " ELSE {$table}.{$colValue} + 1 END,")
            . " {$colExpiry} = EXCLUDED.{$colExpiry}"
            . " RETURNING {$colValue}";

        $stmt = $this->stmt('increment', $sql);
        $stmt->execute(['key' => $key, 'expires_at' => $windowEnd, 'now' => $now]);

        /** @var array{cache_value: string}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        return $row !== false ? (int) $row['cache_value'] : 1;
    }

    /**
     * MySQL: upsert + SELECT in a transaction (no RETURNING support).
     *
     * Uses VALUES() syntax for compatibility with MariaDB and MySQL < 8.0.19.
     */
    private function incrementWithTransaction(string $key, int $windowEnd, int $now): int
    {
        $colKey = $this->quoteColumn('cache_key');
        $colValue = $this->quoteColumn('cache_value');
        $colExpiry = $this->quoteColumn('expires_at');

        $upsertSql = "INSERT INTO {$this->quotedTable} ({$colKey}, {$colValue}, {$colExpiry})"
            . " VALUES (:key, '1', :expires_at)"
            . " ON DUPLICATE KEY UPDATE"
            . " {$colValue} = CASE"
            . " WHEN {$colExpiry} IS NOT NULL AND {$colExpiry} <= :now THEN '1'"
            . " ELSE {$colValue} + 1 END,"
            . " {$colExpiry} = VALUES({$colExpiry})";

        $readSql = "SELECT {$colValue} FROM {$this->quotedTable} WHERE {$colKey} = :key";

        $this->pdo->beginTransaction();

        try {
            $this->stmt('increment_upsert', $upsertSql)->execute([
                'key' => $key,
                'expires_at' => $windowEnd,
                'now' => $now,
            ]);

            $readStmt = $this->stmt('increment_read', $readSql);
            $readStmt->execute(['key' => $key]);

            /** @var array{cache_value: string}|false $row */
            $row = $readStmt->fetch(PDO::FETCH_ASSOC);
            $readStmt->closeCursor();

            $this->pdo->commit();

            return $row !== false ? (int) $row['cache_value'] : 1;
        } catch (\Throwable $throwable) {
            $this->pdo->rollBack();
            throw $throwable;
        }
    }

    // ── Upsert (set/overwrite) ──────────────────────────────────────────

    private function upsert(string $key, string $encodedValue, ?int $expiresAt): void
    {
        $colKey = $this->quoteColumn('cache_key');
        $colValue = $this->quoteColumn('cache_value');
        $colExpiry = $this->quoteColumn('expires_at');

        $sql = match ($this->driverName) {
            'sqlite' => "INSERT OR REPLACE INTO {$this->quotedTable}"
                . " ({$colKey}, {$colValue}, {$colExpiry}) VALUES (:key, :value, :expires_at)",
            'pgsql' => "INSERT INTO {$this->quotedTable}"
                . " ({$colKey}, {$colValue}, {$colExpiry}) VALUES (:key, :value, :expires_at)"
                . " ON CONFLICT ({$colKey}) DO UPDATE SET"
                . " {$colValue} = EXCLUDED.{$colValue}, {$colExpiry} = EXCLUDED.{$colExpiry}",
            'mysql' => "INSERT INTO {$this->quotedTable}"
                . " ({$colKey}, {$colValue}, {$colExpiry}) VALUES (:key, :value, :expires_at)"
                . " ON DUPLICATE KEY UPDATE"
                . " {$colValue} = VALUES({$colValue}), {$colExpiry} = VALUES({$colExpiry})",
        };

        $this->stmt('upsert', $sql)->execute([
            'key' => $key,
            'value' => $encodedValue,
            'expires_at' => $expiresAt,
        ]);
    }

    // ── Identifier quoting ──────────────────────────────────────────────

    /**
     * Shorthand for quoting a single column name.
     */
    private function quoteColumn(string $identifier): string
    {
        return $this->quoteChar
            . str_replace($this->quoteChar, $this->quoteChar . $this->quoteChar, $identifier)
            . $this->quoteChar;
    }

    // ── Table management ────────────────────────────────────────────────

    private function ensureTable(): void
    {
        if ($this->tableCreated) {
            return;
        }

        $colKey = $this->quoteColumn('cache_key');
        $colValue = $this->quoteColumn('cache_value');
        $colExpiry = $this->quoteColumn('expires_at');

        $keyClause = $this->driverName === 'mysql'
            ? ' CHARACTER SET ascii COLLATE ascii_bin'
            : '';

        $createSql = "CREATE TABLE IF NOT EXISTS {$this->quotedTable} ("
            . "{$colKey} VARCHAR(255){$keyClause} NOT NULL PRIMARY KEY, "
            . "{$colValue} TEXT NOT NULL, "
            . "{$colExpiry} BIGINT NULL)";

        try {
            $this->pdo->exec($createSql);
        } catch (\PDOException $pdoException) {
            if ($this->tableExists()) {
                $this->tableCreated = true;
                return;
            }

            throw new \RuntimeException(
                "PdoCache: Failed to create table {$this->quotedTable}. "
                . "If the database user lacks CREATE TABLE privileges, create it manually:\n"
                . $createSql,
                previous: $pdoException,
            );
        }

        $this->tableCreated = true;
    }

    private function tableExists(): bool
    {
        try {
            $this->pdo->prepare("SELECT 1 FROM {$this->quotedTable} LIMIT 1")->execute();
            return true;
        } catch (\PDOException) {
            return false;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

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
     * Get or create a cached prepared statement.
     */
    private function stmt(string $name, string $sql): PDOStatement
    {
        return $this->statements[$name] ??= $this->pdo->prepare($sql);
    }

    /**
     * Probabilistically prune expired entries (~1% of operations).
     *
     * For MySQL and PostgreSQL, the DELETE is limited to 1000 rows per invocation
     * to avoid long-running deletes under high write load. SQLite does not support
     * LIMIT on DELETE directly, so a subquery on rowid is used instead.
     */
    private function maybePruneExpired(): void
    {
        if (mt_rand(1, 100) > 1) {
            return;
        }

        $colExpiry = $this->quoteColumn('expires_at');
        $colKey = $this->quoteColumn('cache_key');

        $sql = match ($this->driverName) {
            'mysql' => "DELETE FROM {$this->quotedTable}"
                . " WHERE {$colExpiry} IS NOT NULL AND {$colExpiry} <= :now"
                . " LIMIT 1000",
            'pgsql' => "DELETE FROM {$this->quotedTable}"
                . " WHERE {$colKey} IN ("
                . " SELECT {$colKey} FROM {$this->quotedTable}"
                . " WHERE {$colExpiry} IS NOT NULL AND {$colExpiry} <= :now"
                . " LIMIT 1000)",
            'sqlite' => "DELETE FROM {$this->quotedTable}"
                . " WHERE rowid IN ("
                . " SELECT rowid FROM {$this->quotedTable}"
                . " WHERE {$colExpiry} IS NOT NULL AND {$colExpiry} <= :now"
                . " LIMIT 1000)",
        };

        $this->stmt('prune', $sql)->execute(['now' => time()]);
    }

    /**
     * Validate that the table name contains only safe characters.
     *
     * Accepts simple names (phirewall_cache) and schema-qualified names (myschema.phirewall_cache).
     * Each part must start with a letter or underscore, contain only alphanumeric characters
     * and underscores, and be at most 64 characters long.
     */
    private function validateTableName(string $tableName): void
    {
        $partPattern = '/^[a-zA-Z_]\w{0,63}$/';
        $parts = explode('.', $tableName);

        if (count($parts) > 2) {
            throw new \InvalidArgumentException(
                'Table name may contain at most one dot (schema.table).',
            );
        }

        foreach ($parts as $part) {
            if (preg_match($partPattern, $part) !== 1) {
                throw new \InvalidArgumentException(
                    'Each part of the table name must start with a letter or underscore, contain only alphanumeric '
                    . 'characters and underscores, and be at most 64 characters long.',
                );
            }
        }
    }
}
