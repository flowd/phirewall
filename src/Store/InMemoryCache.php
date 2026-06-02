<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

final class InMemoryCache implements CacheInterface, CounterStoreInterface
{
    use KeyValidationTrait;
    use BulkCacheOperationsTrait;

    private const PURGE_INTERVAL = 1000;

    /** @var array<string, array{value:mixed,expires:float|null}> */
    private array $data = [];

    private int $operationsSinceLastPurge = 0;

    public function __construct(private readonly ?ClockInterface $clock = null)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->validateKey($key);
        $this->maybePurge();

        if (!isset($this->data[$key])) {
            return $default;
        }

        $entry = $this->data[$key];
        if ($entry['expires'] !== null && $entry['expires'] < $this->now()) {
            unset($this->data[$key]);
            return $default;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->validateKey($key);
        $expires = $this->computeExpiry($ttl);
        $this->data[$key] = ['value' => $value, 'expires' => $expires];
        $this->maybePurge();
        return true;
    }

    public function delete(string $key): bool
    {
        $this->validateKey($key);
        unset($this->data[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->data = [];
        return true;
    }

    public function has(string $key): bool
    {
        $this->validateKey($key);
        $this->maybePurge();

        if (!isset($this->data[$key])) {
            return false;
        }

        if ($this->data[$key]['expires'] !== null && $this->data[$key]['expires'] < $this->now()) {
            unset($this->data[$key]);
            return false;
        }

        return true;
    }

    /**
     * Non-atomic increment helper for our use. Returns new value.
     */
    public function increment(string $key, int $period): int
    {
        $this->validateKey($key);
        $now = $this->now();
        // Align expiry to the end of the current fixed window
        $windowStart = floor($now / $period) * $period;
        $windowEnd = $windowStart + $period;
        $entry = $this->data[$key] ?? ['value' => 0, 'expires' => $windowEnd];
        if ($entry['expires'] !== null && $entry['expires'] < $now) {
            $entry = ['value' => 0, 'expires' => $windowEnd];
        } else {
            // If existing entry's window is different (e.g., first increment after crossing boundary)
            // move expiry to current window end
            $entry['expires'] = $windowEnd;
        }

        if (!is_int($entry['value'])) {
            $entry['value'] = is_scalar($entry['value']) ? (int)$entry['value'] : 0;
        }

        ++$entry['value'];
        $this->data[$key] = $entry;
        $this->maybePurge();
        return $entry['value'];
    }

    public function ttlRemaining(string $key): int
    {
        $this->validateKey($key);
        $entry = $this->data[$key] ?? null;
        if ($entry === null || $entry['expires'] === null) {
            return 0;
        }

        $now = $this->now();
        $remaining = (int)ceil($entry['expires'] - $now);
        return max(0, $remaining);
    }

    private function computeExpiry(null|int|DateInterval $timeToLive): ?float
    {
        if ($timeToLive === null) {
            return null;
        }

        if ($timeToLive instanceof DateInterval) {
            $currentDateTime = new \DateTimeImmutable();
            $expires = $currentDateTime->add($timeToLive)->getTimestamp();
            return (float)$expires;
        }

        return $this->now() + $timeToLive;
    }

    public function purgeExpired(): void
    {
        $now = $this->now();
        foreach ($this->data as $key => $entry) {
            if ($entry['expires'] !== null && $entry['expires'] < $now) {
                unset($this->data[$key]);
            }
        }

        $this->operationsSinceLastPurge = 0;
    }

    private function maybePurge(): void
    {
        if (++$this->operationsSinceLastPurge >= self::PURGE_INTERVAL) {
            $this->purgeExpired();
        }
    }

    /**
     * Current time as a float second timestamp, taken from the injected clock
     * when present and falling back to {@see microtime()} otherwise.
     */
    private function now(): float
    {
        return $this->clock?->now() ?? microtime(true);
    }
}
