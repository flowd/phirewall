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
 */
final readonly class RedisCache implements CacheInterface, CounterStoreInterface
{
    public function __construct(
        private ClientInterface $client,
        private string $namespace = 'Phirewall:'
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->client->get($this->prefixKey($key));
        if ($value === null) {
            return $default;
        }

        return $this->unserializeValue($value);
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
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
        $keyMapping = [];
        $namespacedKeys = [];
        foreach ($keys as $key) {
            $stringKey = (string)$key;
            $keyMapping[$this->prefixKey($stringKey)] = $stringKey;
            $namespacedKeys[] = $this->prefixKey($stringKey);
        }

        $values = $namespacedKeys === [] ? [] : $this->client->mget($namespacedKeys);
        $result = [];
        $index = 0;
        foreach ($keyMapping as $original) {
            $raw = $values[$index] ?? null;
            $result[$original] = $raw === null ? $default : $this->unserializeValue($raw);
            ++$index;
        }

        return $result;
    }

    /**
     * @param iterable<string|int, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $ttlSeconds = $ttl === null ? null : $this->ttlToSeconds($ttl);
        foreach ($values as $key => $value) {
            $this->set((string)$key, $value, $ttlSeconds);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $namespacedKeys = [];
        foreach ($keys as $key) {
            $namespacedKeys[] = $this->prefixKey((string)$key);
        }

        if ($namespacedKeys !== []) {
            $this->client->del($namespacedKeys);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return (bool)$this->client->exists($this->prefixKey($key));
    }

    /**
     * Atomic fixed-window increment aligned to the end of the current window.
     * Returns the new counter value.
     */
    public function increment(string $key, int $period): int
    {
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
        } catch (\Throwable) {
            // In case of Redis errors, fail open and report 0 so callers can decide how to handle.
            return 0;
        }

        return is_scalar($counter) ? (int) $counter : 0;
    }

    public function ttlRemaining(string $key): int
    {
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

    private function serializeValue(mixed $value): string
    {
        // Scalars are stored as strings; everything else JSON-encoded for portability
        if (is_int($value) || is_float($value) || is_string($value)) {
            return (string)$value;
        }

        if ($value === null) {
            return 'null';
        }

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

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
