<?php

/**
 * Example 13: Storage Backend Benchmarks
 *
 * This example benchmarks the performance of different storage backends:
 * - InMemoryCache: Best for single-server deployments
 * - ApcuCache: Good for single-server production
 * - RedisCache: Required for multi-server deployments
 *
 * Features shown:
 * - Increment operation performance
 * - TTL checking performance
 * - Comparison across backends
 *
 * Optional dependencies:
 * - APCu extension for ApcuCache
 * - predis/predis for RedisCache
 *
 * Run: php examples/13-benchmarks.php
 *
 * Environment:
 *   REDIS_URL=redis://localhost:6379/0 (optional)
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Store\ApcuCache;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Store\RedisCache;

echo "=== Storage Backend Benchmarks ===\n\n";

// =============================================================================
// BENCHMARK FUNCTION
// =============================================================================

function benchmark(string $name, callable $fn, int $iterations = 100_000): array
{
    // Warm up
    $fn(100);

    // Actual benchmark
    $start = microtime(true);
    $fn($iterations);
    $elapsed = microtime(true) - $start;

    $opsPerSec = $iterations / max(1e-9, $elapsed);

    return [
        'name' => $name,
        'iterations' => $iterations,
        'elapsed_ms' => $elapsed * 1000,
        'ops_per_sec' => $opsPerSec,
    ];
}

function formatResult(array $result): string
{
    return sprintf(
        "%-25s: %8.3f ms, %9.0f ops/sec",
        $result['name'],
        $result['elapsed_ms'],
        $result['ops_per_sec']
    );
}

$results = [];
$period = 5; // seconds; large enough to avoid rollover during tight loop

// =============================================================================
// IN-MEMORY BENCHMARKS
// =============================================================================

echo "=== InMemoryCache Benchmarks ===\n\n";

$mem = new InMemoryCache();
$keyBase = 'bench:mem:' . bin2hex(random_bytes(4));

$result = benchmark('InMemory increment', function (int $n) use ($mem, $period, $keyBase): void {
    for ($i = 0; $i < $n; ++$i) {
        $mem->increment($keyBase . ':' . ($i % 16), $period);
    }
});
echo formatResult($result) . "\n";
$results['inmemory_increment'] = $result;

// Prepare keys for TTL test
for ($i = 0; $i < 16; ++$i) {
    $mem->set($keyBase . ':ttl:' . $i, 1, 10);
}

$result = benchmark('InMemory ttlRemaining', function (int $n) use ($mem, $keyBase): void {
    for ($i = 0; $i < $n; ++$i) {
        $mem->ttlRemaining($keyBase . ':ttl:' . ($i % 16));
    }
});
echo formatResult($result) . "\n\n";
$results['inmemory_ttl'] = $result;

// =============================================================================
// APCU BENCHMARKS (if available)
// =============================================================================

echo "=== ApcuCache Benchmarks ===\n\n";

try {
    $apcu = new ApcuCache();
    $keyBase = 'bench:apcu:' . bin2hex(random_bytes(4));

    $result = benchmark('APCu increment', function (int $n) use ($apcu, $period, $keyBase): void {
        for ($i = 0; $i < $n; ++$i) {
            $apcu->increment($keyBase . ':' . ($i % 16), $period);
        }
    });
    echo formatResult($result) . "\n";
    $results['apcu_increment'] = $result;

    // Prepare keys for TTL test
    for ($i = 0; $i < 16; ++$i) {
        $apcu->set($keyBase . ':ttl:' . $i, 1, 10);
    }

    $result = benchmark('APCu ttlRemaining', function (int $n) use ($apcu, $keyBase): void {
        for ($i = 0; $i < $n; ++$i) {
            $apcu->ttlRemaining($keyBase . ':ttl:' . ($i % 16));
        }
    });
    echo formatResult($result) . "\n\n";
    $results['apcu_ttl'] = $result;

} catch (Throwable $throwable) {
    echo "[SKIP] APCu not available: " . $throwable->getMessage() . "\n";
    echo "       Enable APCu extension for CLI: apc.enable_cli=1\n\n";
}

// =============================================================================
// REDIS BENCHMARKS (if available)
// =============================================================================

echo "=== RedisCache Benchmarks ===\n\n";

$redisUrl = getenv('REDIS_URL');
if ($redisUrl && class_exists(\Predis\Client::class)) {
    try {
        $client = new \Predis\Client($redisUrl);

        // Verify connectivity
        $pong = (string) $client->ping();
        if (stripos($pong, 'PONG') === false) {
            throw new RuntimeException('Redis PING failed');
        }

        $redis = new RedisCache($client, 'phirewall:bench:');
        $keyBase = 'bench:redis:' . bin2hex(random_bytes(4));

        // Use fewer iterations for Redis (network latency)
        $redisIterations = 10_000;

        $result = benchmark('Redis increment', function (int $n) use ($redis, $period, $keyBase): void {
            for ($i = 0; $i < $n; ++$i) {
                $redis->increment($keyBase . ':' . ($i % 16), $period);
            }
        }, $redisIterations);
        echo formatResult($result) . "\n";
        $results['redis_increment'] = $result;

        // Prepare keys for TTL test
        for ($i = 0; $i < 16; ++$i) {
            $redis->set($keyBase . ':ttl:' . $i, 1, 10);
        }

        $result = benchmark('Redis ttlRemaining', function (int $n) use ($redis, $keyBase): void {
            for ($i = 0; $i < $n; ++$i) {
                $redis->ttlRemaining($keyBase . ':ttl:' . ($i % 16));
            }
        }, $redisIterations);
        echo formatResult($result) . "\n\n";
        $results['redis_ttl'] = $result;

        // Cleanup
        $keys = $client->keys('phirewall:bench:*');
        if (count($keys) > 0) {
            $client->del($keys);
        }

    } catch (Throwable $e) {
        echo "[SKIP] Redis benchmarks failed: " . $e->getMessage() . "\n\n";
    }
} else {
    if ($redisUrl === '' || $redisUrl === '0' || $redisUrl === [] || $redisUrl === false) {
        echo "[SKIP] Set REDIS_URL environment variable to include Redis benchmarks\n";
    }

    if (!class_exists(\Predis\Client::class)) {
        echo "[SKIP] Install predis/predis to include Redis benchmarks\n";
    }

    echo "\n";
}

// =============================================================================
// SUMMARY
// =============================================================================

echo "=== Summary ===\n\n";

echo "Increment Performance (ops/sec):\n";
if (isset($results['inmemory_increment'])) {
    echo "  InMemory: " . number_format($results['inmemory_increment']['ops_per_sec']) . "\n";
}

if (isset($results['apcu_increment'])) {
    echo "  APCu:     " . number_format($results['apcu_increment']['ops_per_sec']) . "\n";
}

if (isset($results['redis_increment'])) {
    echo "  Redis:    " . number_format($results['redis_increment']['ops_per_sec']) . "\n";
}

echo "\n";

echo "TTL Check Performance (ops/sec):\n";
if (isset($results['inmemory_ttl'])) {
    echo "  InMemory: " . number_format($results['inmemory_ttl']['ops_per_sec']) . "\n";
}

if (isset($results['apcu_ttl'])) {
    echo "  APCu:     " . number_format($results['apcu_ttl']['ops_per_sec']) . "\n";
}

if (isset($results['redis_ttl'])) {
    echo "  Redis:    " . number_format($results['redis_ttl']['ops_per_sec']) . "\n";
}

echo "\n";

// =============================================================================
// RECOMMENDATIONS
// =============================================================================

echo "=== Recommendations ===\n\n";

echo "Backend Selection Guide:\n\n";

echo "1. Development/Testing:\n";
echo "   Use InMemoryCache - fastest, no dependencies\n\n";

echo "2. Single Server Production:\n";
echo "   Use ApcuCache - fast, persistent across requests\n";
echo "   Fallback to InMemoryCache if APCu unavailable\n\n";

echo "3. Multi-Server Production:\n";
echo "   Use RedisCache - shared state across servers\n";
echo "   Consider Redis Cluster for high availability\n\n";

echo "4. Hybrid Approach:\n";
echo "   Use APCu for hot path (throttle checks)\n";
echo "   Use Redis for shared state (Fail2Ban bans)\n\n";

echo "Performance Notes:\n";
echo "- InMemory is ~100x faster than Redis\n";
echo "- APCu is ~10x faster than Redis\n";
echo "- Redis latency depends on network distance\n";
echo "- Consider connection pooling for Redis\n";

echo "\n=== Example Complete ===\n";
