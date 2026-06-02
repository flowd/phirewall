<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use DateInterval;

/**
 * Default PSR-16 bulk operations expressed in terms of the single-key methods.
 *
 * Backends that have no native batch primitive (such as {@see InMemoryCache}
 * and {@see ApcuCache}) get correct {@see getMultiple()}, {@see setMultiple()}
 * and {@see deleteMultiple()} implementations for free by using this trait and
 * only implementing get/set/delete/has themselves.
 *
 * Backends that can batch (for example {@see PdoCache} with `IN (...)` queries
 * or {@see RedisCache} with `MGET`/`DEL`) keep their own faster overrides; this
 * trait only fills in the methods they do not override.
 *
 * Requires {@see KeyValidationTrait} for the key-validation helpers used here.
 */
trait BulkCacheOperationsTrait
{
    abstract public function get(string $key, mixed $default = null): mixed;

    abstract public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool;

    abstract public function delete(string $key): bool;

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($this->validateKeyList($keys) as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $allStored = true;
        foreach ($this->validateKeyedValues($values) as $key => $value) {
            // set() first so every write runs even after one fails (no short-circuit).
            $allStored = $this->set($key, $value, $ttl) && $allStored;
        }

        return $allStored;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $allDeleted = true;
        foreach ($this->validateKeyList($keys) as $key) {
            // delete() first so every key is attempted even after one fails.
            $allDeleted = $this->delete($key) && $allDeleted;
        }

        return $allDeleted;
    }
}
