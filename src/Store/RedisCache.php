<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use DateTimeImmutable;
use Predis\ClientInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Redis-backed PSR-16 cache with helpers for Phirewall fixed-window counters.
 *
 * Requires a Predis ClientInterface (pure PHP, no server extension required).
 *
 * Serialization contract (read this before storing arbitrary values):
 *
 * This backend is used by Phirewall only for integer counters (via
 * {@see increment()}) and JSON-encodable structures. Values are stored as plain
 * Redis strings: int and string values are written verbatim and floats via a
 * `(string)` cast (so float round-trips are subject to that formatting), null as
 * the literal `'null'`, and booleans, arrays and objects are JSON encoded
 * ({@see serializeValue()}). There is no type tag in the stored payload, so
 * {@see unserializeValue()} reconstructs the type by sniffing the string on
 * read: `'null'` becomes null, a numeric string becomes int/float, a string
 * that parses as JSON (e.g. `'true'`, `'[1,2]'`) becomes the decoded value, and
 * anything else stays a string. This is lossy for string values that happen to look like another
 * type: storing the literal strings `"null"`, `"123"` or `"[1,2]"` reads back as
 * null, 123 or [1, 2] respectively. That mismatch never occurs for Phirewall's
 * own usage (integer counters and JSON documents), so the format is intentional
 * and must not be changed without introducing a typed envelope.
 */
final readonly class RedisCache implements CacheInterface, CounterStoreInterface
{
    use KeyValidationTrait;

    public function __construct(
        private ClientInterface $client,
        private string $namespace = 'Phirewall:'
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->validateKey($key);
        $value = $this->client->get($this->prefixKey($key));
        if ($value === null) {
            return $default;
        }

        return $this->unserializeValue($value);
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->validateKey($key);
        $namespacedKey = $this->prefixKey($key);
        $payload = $this->serializeValue($value);
        if ($ttl === null) {
            $this->client->set($namespacedKey, $payload);
            return true;
        }

        $seconds = $this->ttlToSeconds($ttl);
        // Use EX for seconds precision to keep parity with windowing
        $this->client->set($namespacedKey, $payload, 'EX', $seconds);
        return true;
    }

    public function delete(string $key): bool
    {
        $this->validateKey($key);
        $this->client->del([$this->prefixKey($key)]);
        return true;
    }

    public function clear(): bool
    {
        // Best-effort: delete keys with our namespace
        $cursor = '0';
        do {
            /** @var array{0:string,1:array<int,string>} $scan */
            $scan = $this->client->scan($cursor, ['MATCH' => $this->namespace . '*', 'COUNT' => 1000]);
            $cursor = (string)$scan[0];
            $keys = $scan[1];
            if ($keys !== []) {
                $this->client->del($keys);
            }
        } while ($cursor !== '0');

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $orderedKeys = $this->validateKeyList($keys);
        $namespacedKeys = array_map($this->prefixKey(...), $orderedKeys);

        $values = $namespacedKeys === [] ? [] : $this->client->mget($namespacedKeys);
        $result = [];
        foreach ($orderedKeys as $index => $original) {
            $raw = $values[$index] ?? null;
            $result[$original] = $raw === null ? $default : $this->unserializeValue($raw);
        }

        return $result;
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $ttlSeconds = $ttl === null ? null : $this->ttlToSeconds($ttl);
        foreach ($this->validateKeyedValues($values) as $key => $value) {
            $this->set($key, $value, $ttlSeconds);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $namespacedKeys = array_map($this->prefixKey(...), $this->validateKeyList($keys));

        if ($namespacedKeys !== []) {
            $this->client->del($namespacedKeys);
        }

        return true;
    }

    public function has(string $key): bool
    {
        $this->validateKey($key);
        return (bool)$this->client->exists($this->prefixKey($key));
    }

    /**
     * Atomic fixed-window increment aligned to the end of the current window.
     * Returns the new counter value.
     *
     * Errors from the underlying Redis client (connection refused, AUTH failure,
     * Lua script error, etc.) are re-thrown so that
     * {@see \Flowd\Phirewall\Middleware::process()} can apply the configured
     * fail-open / fail-closed policy. A diagnostic `E_USER_WARNING` is emitted
     * via {@see trigger_error()} before the throw so the failure remains
     * observable even when callers later suppress the exception.
     *
     * @throws \Throwable Re-thrown from the Predis client on infrastructure
     *                    errors. Concrete type depends on the Predis backend.
     */
    public function increment(string $key, int $period): int
    {
        $this->validateKey($key);
        $namespacedKey = $this->prefixKey($key);
        $now = time();
        $windowStart = intdiv($now, $period) * $period;
        $windowEnd = $windowStart + $period; // unix timestamp (seconds)

        $script = <<<'LUA'
        local key = KEYS[1]
        local window_end = tonumber(ARGV[1])
        local val = redis.call('INCR', key)
        -- If this is the first hit for this window, align expiry to window_end
        if val == 1 then
            redis.call('EXPIREAT', key, window_end)
        end
        return val
LUA;

        try {
            $counter = $this->client->eval($script, 1, $namespacedKey, (string)$windowEnd);
        } catch (\Throwable $throwable) {
            // Diagnostic visibility: emit a warning so operators see infrastructure
            // failures even when an upstream catch converts the exception. Some
            // frameworks install error handlers that re-throw on E_USER_WARNING;
            // the inner try/catch swallows that upgrade so the original Redis
            // exception is the one that ultimately surfaces.
            try {
                trigger_error(
                    sprintf('RedisCache::increment() failed for key "%s": %s', $key, $throwable->getMessage()),
                    E_USER_WARNING,
                );
            } catch (\Throwable) {
                // Diagnostic warning was upgraded to an exception by a hostile
                // error handler; ignore and surface the underlying Redis error.
            }

            throw $throwable;
        }

        return is_scalar($counter) ? (int) $counter : 0;
    }

    public function ttlRemaining(string $key): int
    {
        $this->validateKey($key);
        $ttl = $this->client->ttl($this->prefixKey($key));
        return max($ttl, 0);
    }

    private function prefixKey(string $key): string
    {
        return $this->namespace . $key;
    }

    private function ttlToSeconds(int|DateInterval $ttl): int
    {
        if (is_int($ttl)) {
            return $ttl;
        }

        $dateTime = new DateTimeImmutable();
        return $dateTime->add($ttl)->getTimestamp() - $dateTime->getTimestamp();
    }

    /**
     * Encode a value for storage. int/float/string values are written verbatim,
     * null as the literal `'null'`, and booleans, arrays and objects as JSON. See
     * the class-level serialization contract: the encoding is untagged and only
     * round-trips losslessly for Phirewall's integer counters and JSON structures.
     */
    private function serializeValue(mixed $value): string
    {
        // int/float/string verbatim; null, booleans, arrays and objects fall through below.
        if (is_int($value) || is_float($value) || is_string($value)) {
            return (string)$value;
        }

        if ($value === null) {
            return 'null';
        }

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Reconstruct a value from its stored string by type-sniffing (see the
     * class-level serialization contract). Re-typing numeric/JSON/'null'-looking
     * strings is intentional and safe for Phirewall's integer counters and
     * JSON structures; it is lossy for string values that mimic those forms.
     */
    private function unserializeValue(string $raw): mixed
    {
        // Try to detect JSON objects/arrays/null, otherwise return string/int
        if ($raw === 'null') {
            return null;
        }

        // If numeric, cast accordingly
        if (is_numeric($raw)) {
            if (ctype_digit($raw)) {
                return (int)$raw;
            }

            return (float)$raw;
        }

        // Attempt JSON decode; if fails, return raw string
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            return $decoded;
        } catch (\Throwable) {
            return $raw;
        }
    }
}
