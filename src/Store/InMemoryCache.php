<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

final class InMemoryCache implements CacheInterface, CounterStoreInterface
{
    /** @var array<string, array{value:mixed,expires:float|null}> */
    private array $data = [];

    public function __construct(private readonly ?ClockInterface $clock = null)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->purgeExpired();
        if (!isset($this->data[$key])) {
            return $default;
        }

        $entry = $this->data[$key];
        $now = $this->clock?->now() ?? microtime(true);
        if ($entry['expires'] !== null && $entry['expires'] < $now) {
            unset($this->data[$key]);
            return $default;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $expires = $this->computeExpiry($ttl);
        $this->data[$key] = ['value' => $value, 'expires' => $expires];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->data = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
         * @param iterable<string|int, mixed> $values
         */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string)$key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string)$key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        $this->purgeExpired();
        $now = $this->clock?->now() ?? microtime(true);
        return isset($this->data[$key]) && ($this->data[$key]['expires'] === null || $this->data[$key]['expires'] >= $now);
    }

    /**
     * Non-atomic increment helper for our use. Returns new value.
     */
    public function increment(string $key, int $period): int
    {
        $now = $this->clock?->now() ?? microtime(true);
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
        return $entry['value'];
    }

    public function ttlRemaining(string $key): int
    {
        $entry = $this->data[$key] ?? null;
        if ($entry === null || $entry['expires'] === null) {
            return 0;
        }

        $now = $this->clock?->now() ?? microtime(true);
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

        $now = $this->clock?->now() ?? microtime(true);
        return $now + $timeToLive;
    }

    private function purgeExpired(): void
    {
        $now = $this->clock?->now() ?? microtime(true);
        foreach ($this->data as $key => $entry) {
            if ($entry['expires'] !== null && $entry['expires'] < $now) {
                unset($this->data[$key]);
            }
        }
    }
}
