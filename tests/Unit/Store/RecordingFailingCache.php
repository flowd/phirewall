<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use DateInterval;
use Flowd\Phirewall\Store\BulkCacheOperationsTrait;
use Flowd\Phirewall\Store\KeyValidationTrait;
use Psr\SimpleCache\CacheInterface;

/**
 * Test double that exercises {@see BulkCacheOperationsTrait}: its single-key
 * set()/delete() report failure for any key containing "fail" and record every
 * attempted key, so tests can assert the bulk methods aggregate results without
 * short-circuiting on the first failure.
 */
final class RecordingFailingCache implements CacheInterface
{
    use BulkCacheOperationsTrait;
    use KeyValidationTrait;

    /** @var list<string> */
    public array $setAttempts = [];

    /** @var list<string> */
    public array $deleteAttempts = [];

    /** @var array<string, mixed> */
    private array $store = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->store) ? $this->store[$key] : $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->setAttempts[] = $key;
        if (str_contains($key, 'fail')) {
            return false;
        }

        $this->store[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        $this->deleteAttempts[] = $key;

        return !str_contains($key, 'fail');
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }

    public function clear(): bool
    {
        $this->store = [];

        return true;
    }
}
