<?php

/**
 * Example 20: Firewall Rule Benchmarks
 *
 * Benchmarks the overhead of the Firewall::decide() loop with various
 * rule configurations to catch performance regressions.
 *
 * Scenarios:
 * - Baseline (no rules)
 * - Allow2Ban (1 rule, 10 rules)
 * - Fail2Ban (1 rule)
 * - Throttle (1 rule)
 * - Mixed (5 allow2ban + 5 fail2ban + 5 throttle)
 *
 * All benchmarks use InMemoryCache -- no external dependencies required.
 *
 * Run: php examples/20-rule-benchmarks.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Firewall Rule Benchmarks ===\n\n";

// =============================================================================
// BENCHMARK HELPERS
// =============================================================================

$iterations = 10_000;

function benchmarkRule(string $name, Config $config, int $iterations): array
{
    $firewall = new Firewall($config);

    // Warm up with 100 iterations
    for ($i = 0; $i < 100; ++$i) {
        $ip = sprintf('172.16.%d.%d', $i >> 8, $i & 0xFF);
        $request = new ServerRequest('GET', '/api/resource', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
        $firewall->decide($request);
    }

    // Re-create firewall + cache to start clean
    $freshCache = new InMemoryCache();

    // Rebuild config with a fresh cache for the actual run
    $freshConfig = new Config($freshCache);

    // Copy rule sections from original config
    foreach ($config->allow2ban->rules() as $throttleRule) {
        $freshConfig->allow2ban->addRule($throttleRule);
    }

    foreach ($config->fail2ban->rules() as $throttleRule) {
        $freshConfig->fail2ban->addRule($throttleRule);
    }

    foreach ($config->throttles->rules() as $throttleRule) {
        $freshConfig->throttles->addRule($throttleRule);
    }

    $firewall = new Firewall($freshConfig);

    $startNs = hrtime(true);

    for ($i = 0; $i < $iterations; ++$i) {
        // Unique IP per iteration to avoid hitting thresholds
        $ip = sprintf('10.0.%d.%d', $i >> 8, $i & 0xFF);
        $request = new ServerRequest('GET', '/api/resource', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
        $firewall->decide($request);
    }

    $elapsedNs = hrtime(true) - $startNs;
    $elapsedMs = $elapsedNs / 1_000_000;
    $elapsedSec = $elapsedNs / 1_000_000_000;
    $opsPerSec = $iterations / max(1e-9, $elapsedSec);
    $avgMicros = ($elapsedNs / $iterations) / 1_000;

    return [
        'name' => $name,
        'iterations' => $iterations,
        'elapsed_ms' => $elapsedMs,
        'ops_per_sec' => $opsPerSec,
        'avg_us' => $avgMicros,
    ];
}

function formatRuleResult(array $result): string
{
    return sprintf(
        "%-35s: %8.1f ms, %9.0f ops/sec, %7.2f us/op",
        $result['name'],
        $result['elapsed_ms'],
        $result['ops_per_sec'],
        $result['avg_us']
    );
}

$ipExtractor = fn($req): string => $req->getServerParams()['REMOTE_ADDR'];
$alwaysMatchFilter = fn($req): bool => true;
$neverMatchFilter = fn($req): bool => false;

$results = [];

// =============================================================================
// 1) BASELINE: No rules configured
// =============================================================================

echo "--- Baseline (no rules) ---\n";

$config = new Config(new InMemoryCache());
$result = benchmarkRule('Baseline (no rules)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// 2) ALLOW2BAN: 1 rule
// =============================================================================

echo "--- Allow2Ban (1 rule) ---\n";

$config = new Config(new InMemoryCache());
$config->allow2ban->add(
    name: 'a2b-bench',
    threshold: 100_000, // High threshold to avoid bans during benchmark
    period: 3600,
    banSeconds: 3600,
    key: $ipExtractor,
);

$result = benchmarkRule('Allow2Ban (1 rule)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// 3) ALLOW2BAN: 10 rules
// =============================================================================

echo "--- Allow2Ban (10 rules) ---\n";

$config = new Config(new InMemoryCache());
for ($r = 0; $r < 10; ++$r) {
    $config->allow2ban->add(
        name: 'a2b-bench-' . $r,
        threshold: 100_000,
        period: 3600,
        banSeconds: 3600,
        key: $ipExtractor,
    );
}

$result = benchmarkRule('Allow2Ban (10 rules)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// 4) FAIL2BAN: 1 rule (filter never matches, so only ban-key check runs)
// =============================================================================

echo "--- Fail2Ban (1 rule) ---\n";

$config = new Config(new InMemoryCache());
$config->fail2ban->add(
    name: 'f2b-bench',
    threshold: 100_000,
    period: 3600,
    ban: 3600,
    filter: $neverMatchFilter,  // Filter never matches: measures ban-key lookup overhead
    key: $ipExtractor,
);

$result = benchmarkRule('Fail2Ban (1 rule)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// 5) THROTTLE: 1 rule
// =============================================================================

echo "--- Throttle (1 rule) ---\n";

$config = new Config(new InMemoryCache());
$config->throttles->add(
    name: 'throttle-bench',
    limit: 100_000,  // High limit to avoid throttling during benchmark
    period: 3600,
    key: $ipExtractor,
);

$result = benchmarkRule('Throttle (1 rule)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// 6) MIXED: 5 allow2ban + 5 fail2ban + 5 throttle
// =============================================================================

echo "--- Mixed (5 a2b + 5 f2b + 5 throttle) ---\n";

$config = new Config(new InMemoryCache());

for ($r = 0; $r < 5; ++$r) {
    $config->allow2ban->add(
        name: 'a2b-mixed-' . $r,
        threshold: 100_000,
        period: 3600,
        banSeconds: 3600,
        key: $ipExtractor,
    );
}

for ($r = 0; $r < 5; ++$r) {
    $config->fail2ban->add(
        name: 'f2b-mixed-' . $r,
        threshold: 100_000,
        period: 3600,
        ban: 3600,
        filter: $neverMatchFilter,
        key: $ipExtractor,
    );
}

for ($r = 0; $r < 5; ++$r) {
    $config->throttles->add(
        name: 'throttle-mixed-' . $r,
        limit: 100_000,
        period: 3600,
        key: $ipExtractor,
    );
}

$result = benchmarkRule('Mixed (5+5+5 rules)', $config, $iterations);
echo formatRuleResult($result) . "\n\n";
$results[] = $result;

// =============================================================================
// SUMMARY
// =============================================================================

echo "=== Summary ===\n\n";

echo sprintf("%-35s  %10s  %10s  %10s\n", 'Scenario', 'ops/sec', 'avg us/op', 'elapsed ms');
echo str_repeat('-', 75) . "\n";

foreach ($results as $result) {
    echo sprintf(
        "%-35s  %10s  %10.2f  %10.1f\n",
        $result['name'],
        number_format($result['ops_per_sec']),
        $result['avg_us'],
        $result['elapsed_ms']
    );
}

echo "\n";

// Slowdown factor vs baseline
$baselineOps = $results[0]['ops_per_sec'];
echo "Overhead vs baseline:\n";
for ($i = 1, $iMax = count($results); $i < $iMax; ++$i) {
    $factor = $baselineOps / max(1, $results[$i]['ops_per_sec']);
    echo sprintf(
        "  %-33s  %.2fx slower\n",
        $results[$i]['name'],
        $factor
    );
}

echo "\n=== Benchmark Complete ===\n";
