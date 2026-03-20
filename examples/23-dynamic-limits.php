<?php

/**
 * Example 23: Dynamic Throttle Limits
 *
 * This example demonstrates how to use closures for throttle limits
 * to provide different rate limits based on request properties (e.g. user role).
 *
 * Run: php examples/23-dynamic-limits.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

echo "=== Dynamic Throttle Limits Example ===\n\n";

$cache = new InMemoryCache();
$config = new Config($cache);
$config->enableRateLimitHeaders();

// Dynamic limit: admins get 100 req/min, regular users get 5 req/min
$config->throttles->add(
    'role-based',
    fn(ServerRequestInterface $serverRequest): int => $serverRequest->getHeaderLine('X-Role') === 'admin' ? 100 : 5,
    60,
    fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
);

$firewall = new Firewall($config);

echo "--- Regular user (limit: 5/min) ---\n";
for ($i = 1; $i <= 7; ++$i) {
    $request = new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
    $result = $firewall->decide($request);
    $status = $result->isBlocked() ? 'BLOCKED' : 'PASS';
    echo sprintf("  Request %d: %s\n", $i, $status);
}

echo "\n--- Admin user (limit: 100/min) ---\n";
for ($i = 1; $i <= 7; ++$i) {
    $request = (new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
        ->withHeader('X-Role', 'admin');
    $result = $firewall->decide($request);
    $status = $result->isBlocked() ? 'BLOCKED' : 'PASS';
    echo sprintf("  Request %d: %s\n", $i, $status);
}

echo "\n=== Example Complete ===\n";
