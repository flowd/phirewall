--TEST--
Phirewall: fail-open mode passes request when cache throws an exception
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\SimpleCache\CacheInterface;

$failingCache = new class implements CacheInterface, CounterStoreInterface {
    public function get(string $key, mixed $default = null): mixed
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function delete(string $key): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function clear(): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function deleteMultiple(iterable $keys): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function has(string $key): bool
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function increment(string $key, int $period): int
    {
        throw new \RuntimeException('cache unavailable');
    }

    public function ttlRemaining(string $key): int
    {
        throw new \RuntimeException('cache unavailable');
    }
};

$config = new Config($failingCache);
$config->setFailOpen(true);
$config->throttles->add('test', 10, 60, fn($r) => 'key');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$response = $middleware->process(phpt_request('GET', '/'), $handler);
echo 'status=' . $response->getStatusCode() . "\n";
echo 'handler=' . $response->getHeaderLine('X-Handler') . "\n";
?>
--EXPECT--
status=200
handler=ok
