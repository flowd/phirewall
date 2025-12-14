<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Store\ApcuCache;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Store\RedisCache;

/**
 * Simple micro-benchmark for CounterStoreInterface implementations.
 *
 * Usage:
 *  php examples/benchmarks_counters.php            # In-memory only
 *  REDIS_URL=redis://localhost:6379 php examples/benchmarks_counters.php   # With Redis (if predis installed)
 */

function bench(string $name, callable $fn, int $iterations = 100_000): void
{
    $start = microtime(true);
    $fn($iterations);
    $elapsed = microtime(true) - $start;
    $ops = $iterations / max(1e-9, $elapsed);
    printf("%-22s: %8.3f ms, %9.0f ops/sec\n", $name, $elapsed * 1000, $ops);
}

$period = 5; // seconds; large enough to avoid rollover during tight loop

// In-memory benchmarks
$mem = new InMemoryCache();
$keyBase = 'bench:mem:' . bin2hex(random_bytes(4));

bench('InMemory increment', static function (int $n) use ($mem, $period, $keyBase): void {
    for ($i = 0; $i < $n; ++$i) {
        $mem->increment($keyBase . ':' . ($i % 16), $period);
    }
});

bench('InMemory ttlRemaining', static function (int $n) use ($mem, $keyBase): void {
    // ensure keys exist
    for ($i = 0; $i < 16; ++$i) {
        $mem->set($keyBase . ':ttl:' . $i, 1, 10);
    }

    for ($i = 0; $i < $n; ++$i) {
        $mem->ttlRemaining($keyBase . ':ttl:' . ($i % 16));
    }
});

// Optional Redis benchmarks if predis is available and REDIS_URL set
$redisUrl = getenv('REDIS_URL');
if ($redisUrl && class_exists(\Predis\Client::class)) {
    try {
        $client = new \Predis\Client($redisUrl);
        // simple ping to ensure connectivity
        if ((string)$client->ping() !== 'PONG') {
            throw new RuntimeException('Redis PING failed');
        }

        $redis = new RedisCache($client, 'Phirewall:bench:');
        $rkeyBase = 'bench:redis:' . bin2hex(random_bytes(4));

        bench('Redis increment', static function (int $n) use ($redis, $period, $rkeyBase): void {
            for ($i = 0; $i < $n; ++$i) {
                $redis->increment($rkeyBase . ':' . ($i % 16), $period);
            }
        });

        bench('Redis ttlRemaining', static function (int $n) use ($redis, $rkeyBase): void {
            // ensure keys exist
            for ($i = 0; $i < 16; ++$i) {
                $redis->set($rkeyBase . ':ttl:' . $i, 1, 10);
            }

            for ($i = 0; $i < $n; ++$i) {
                $redis->ttlRemaining($rkeyBase . ':ttl:' . ($i % 16));
            }
        });
    } catch (Throwable $e) {
        fwrite(STDERR, "[WARN] Redis benchmarks skipped: " . $e->getMessage() . "\n");
    }
} elseif ($redisUrl === '' || $redisUrl === '0' || $redisUrl === [] || $redisUrl === false) {
    fwrite(STDERR, "[INFO] Set REDIS_URL and install predis/predis to include Redis benchmarks.\n");
} elseif (!class_exists(\Predis\Client::class)) {
    fwrite(STDERR, "[INFO] Predis not installed; run composer require predis/predis to include Redis benchmarks.\n");
}

// Optional APCU benchmarks if APCU is available
try {
    $mem = new ApcuCache();
    $keyBase = 'bench:apcu:' . bin2hex(random_bytes(4));

    bench('APCU increment', static function (int $n) use ($mem, $period, $keyBase): void {
        for ($i = 0; $i < $n; ++$i) {
            $mem->increment($keyBase . ':' . ($i % 16), $period);
        }
    });

    bench('APCU ttlRemaining', static function (int $n) use ($mem, $keyBase): void {
        // ensure keys exist
        for ($i = 0; $i < 16; ++$i) {
            $mem->set($keyBase . ':ttl:' . $i, 1, 10);
        }

        for ($i = 0; $i < $n; ++$i) {
            $mem->ttlRemaining($keyBase . ':ttl:' . ($i % 16));
        }
    });
} catch (Throwable $e) {
    fwrite(STDERR, "[WARN] APCU benchmarks skipped: " . $e->getMessage() . "\n");
}
