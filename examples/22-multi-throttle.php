<?php

/**
 * Example 22: Multi-Window Throttling
 *
 * This example demonstrates multiThrottle which applies multiple
 * time windows to a single logical throttle (burst + sustained).
 *
 * Run: php examples/22-multi-throttle.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Multi-Window Throttling Example ===\n\n";

$cache = new InMemoryCache();
$config = new Config($cache);
$config->enableRateLimitHeaders();

// Register burst + sustained rate limiting with a single call.
// "api/1s" allows 3 requests per second (burst protection).
// "api/60s" allows 60 requests per minute (sustained throughput).
$config->throttles->multi('api', [
    1  => 3,   // 3 req/s burst limit
    60 => 60,  // 60 req/min sustained limit
], KeyExtractors::ip());

echo "Rules registered:\n";
foreach ($config->throttles->rules() as $name => $rule) {
    $request = new ServerRequest('GET', '/');
    echo sprintf(
        "  - %s: %d requests per %d seconds\n",
        $name,
        $rule->resolveLimit($request),
        $rule->resolvePeriod($request)
    );
}

echo "\n";

$firewall = new Firewall($config);

echo "Sending 5 rapid requests (burst limit is 3/s)...\n\n";

for ($i = 1; $i <= 5; ++$i) {
    $request = new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
    $result = $firewall->decide($request);

    $status = $result->isBlocked() ? 'BLOCKED' : 'PASS';
    $rule = $result->headers['X-Phirewall-Matched'] ?? '-';

    echo sprintf("  Request %d: %s", $i, $status);
    if ($result->isBlocked()) {
        echo sprintf(" (by rule: %s, retry-after: %ss)", $rule, $result->headers['Retry-After'] ?? '?');
    }

    echo "\n";
}

echo "\n=== Example Complete ===\n";
