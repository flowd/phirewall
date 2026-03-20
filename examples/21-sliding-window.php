<?php

/**
 * Example 21: Sliding Window Rate Limiting
 *
 * This example demonstrates the sliding window throttle, which avoids
 * the "double burst" problem at fixed window boundaries.
 *
 * With fixed windows, a client can send `limit` requests at the end of
 * one window and another `limit` at the start of the next, effectively
 * doubling throughput in a short interval. The sliding window algorithm
 * uses a weighted average of the current and previous window counters to
 * produce a smooth estimate that prevents this.
 *
 * Run: php examples/21-sliding-window.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Sliding Window Rate Limiting Example ===\n\n";

$cache = new InMemoryCache();
$config = new Config($cache);

// Sliding window: 10 requests per 60 seconds
$config->throttles->sliding(
    name: 'api-sliding',
    limit: 10,
    period: 60,
    key: KeyExtractors::ip(),
);

echo "Sliding throttle configured: 10 req/60s per IP\n\n";

$firewall = new Firewall($config);
$request = new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

echo "--- Sending 12 requests from the same IP ---\n";
for ($i = 1; $i <= 12; ++$i) {
    $result = $firewall->decide($request);
    $status = $result->isPass() ? 'PASS' : 'THROTTLED';
    echo sprintf("  Request %2d: %s\n", $i, $status);
}

echo "\n";
echo "--- How sliding window prevents the 'double burst' problem ---\n\n";
echo "In a 60-second period with limit=10:\n";
echo "  Fixed window:   10 requests at T=59s + 10 at T=61s = 20 in 2 seconds (allowed!)\n";
echo "  Sliding window: 10 requests at T=59s + 1 at T=61s = blocked\n";
echo "    (estimate = 10 * 59/60 + 1 = ~10.83, exceeds limit)\n\n";

echo "The sliding window considers the weighted contribution of the\n";
echo "previous window's requests, producing a smooth rate limit.\n";

echo "\n=== Example Complete ===\n";
