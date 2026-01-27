<?php

/**
 * Example 03: API Rate Limiting
 *
 * This example demonstrates tiered rate limiting for APIs with:
 * - Global rate limits per IP
 * - Endpoint-specific limits
 * - Authenticated user higher quotas
 * - API key based limiting
 * - Burst detection
 *
 * Run: php examples/03-api-rate-limiting.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== API Rate Limiting Example ===\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache);
$config->enableRateLimitHeaders(); // Send X-RateLimit-* headers

// -----------------------------------------------------------------------------
// Tier 1: Global IP-based limit (baseline protection)
// -----------------------------------------------------------------------------
$config->throttle(
    name: 'global-ip',
    limit: 100,     // 100 requests
    period: 60,     // per minute
    key: KeyExtractors::ip()
);
echo "1. Global limit: 100 req/min per IP\n";

// -----------------------------------------------------------------------------
// Tier 2: Burst detection (prevent rapid-fire requests)
// -----------------------------------------------------------------------------
$config->throttle(
    name: 'burst',
    limit: 20,      // 20 requests
    period: 5,      // in 5 seconds
    key: KeyExtractors::ip()
);
echo "2. Burst limit: 20 req/5s per IP\n";

// -----------------------------------------------------------------------------
// Tier 3: Write operation limits (POST/PUT/DELETE)
// -----------------------------------------------------------------------------
$config->throttle(
    name: 'write-ops',
    limit: 30,
    period: 60,
    key: function (ServerRequestInterface $request): ?string {
        if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
            return $request->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null; // Skip for GET requests
    }
);
echo "3. Write ops limit: 30 req/min per IP\n";

// -----------------------------------------------------------------------------
// Tier 4: Endpoint-specific limits
// -----------------------------------------------------------------------------

// Search endpoint (expensive operation)
$config->throttle(
    name: 'search',
    limit: 10,
    period: 60,
    key: function (ServerRequestInterface $request): ?string {
        if ($request->getUri()->getPath() === '/api/search') {
            return $request->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);
echo "4. Search endpoint: 10 req/min per IP\n";

// Export endpoint (very expensive)
$config->throttle(
    name: 'export',
    limit: 2,
    period: 300, // 5 minutes
    key: function (ServerRequestInterface $request): ?string {
        if (str_starts_with($request->getUri()->getPath(), '/api/export')) {
            return $request->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);
echo "5. Export endpoint: 2 req/5min per IP\n";

// -----------------------------------------------------------------------------
// Tier 5: Authenticated user limits (higher quota)
// -----------------------------------------------------------------------------
$config->throttle(
    name: 'authenticated',
    limit: 1000,
    period: 60,
    key: KeyExtractors::header('X-User-Id')
);
echo "6. Authenticated users: 1000 req/min per user\n";

// -----------------------------------------------------------------------------
// Tier 6: API key limits
// -----------------------------------------------------------------------------
$config->throttle(
    name: 'api-key',
    limit: 500,
    period: 60,
    key: KeyExtractors::header('X-API-Key')
);
echo "7. API key: 500 req/min per key\n";

// -----------------------------------------------------------------------------
// Custom response for rate limiting
// -----------------------------------------------------------------------------
$config->throttledResponse(function (string $rule, int $retryAfter, $request): ResponseInterface {
    return new Response(429, [
        'Content-Type' => 'application/json',
        'Retry-After' => (string) $retryAfter,
    ], json_encode([
        'error' => 'rate_limit_exceeded',
        'message' => "You've exceeded the rate limit. Please try again in {$retryAfter} seconds.",
        'rule' => $rule,
        'retry_after' => $retryAfter,
    ], JSON_THROW_ON_ERROR));
});

echo "\n";

// =============================================================================
// SIMULATION
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'],
            json_encode(['status' => 'ok'], JSON_THROW_ON_ERROR));
    }
};

$test = function (
    string $desc,
    string $method,
    string $path,
    array $headers = [],
    string $ip = '10.0.0.1'
) use ($middleware, $handler): void {
    $request = new ServerRequest($method, $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);
    $status = $response->getStatusCode();

    echo sprintf("  %-55s => %d", $desc, $status);

    // Show rate limit headers
    $remaining = $response->getHeaderLine('X-RateLimit-Remaining');
    $rule = $response->getHeaderLine('X-Phirewall-Matched');

    if ($remaining !== '') {
        echo " [remaining: $remaining]";
    }
    if ($status === 429 && $rule !== '') {
        echo " [rule: $rule]";
    }
    echo "\n";
};

echo "=== Test 1: Burst Detection ===\n";
echo "25 rapid requests should trigger burst limit after 20...\n\n";

$burstIp = '10.0.0.10';
for ($i = 1; $i <= 25; $i++) {
    $test("Burst request $i", 'GET', '/api/users', [], $burstIp);
}

echo "\n=== Test 2: Endpoint-Specific Limits ===\n";
echo "Testing search endpoint (10/min limit)...\n\n";

$searchIp = '10.0.0.20';
for ($i = 1; $i <= 12; $i++) {
    $test("Search request $i", 'GET', '/api/search', [], $searchIp);
}

echo "\nTesting export endpoint (2/5min limit)...\n\n";

$exportIp = '10.0.0.30';
for ($i = 1; $i <= 4; $i++) {
    $test("Export request $i", 'GET', '/api/export/csv', [], $exportIp);
}

echo "\n=== Test 3: Write Operations ===\n";
echo "Testing write operation limits...\n\n";

$writeIp = '10.0.0.40';
// Mix of write operations
for ($i = 1; $i <= 5; $i++) {
    $test("POST /api/items (create)", 'POST', '/api/items', [], $writeIp);
    $test("PUT /api/items/$i (update)", 'PUT', "/api/items/$i", [], $writeIp);
    $test("DELETE /api/items/$i (delete)", 'DELETE', "/api/items/$i", [], $writeIp);
}

echo "\n=== Test 4: Authenticated User (Higher Quota) ===\n";
echo "User with X-User-Id gets 1000/min instead of 100/min...\n\n";

// First, exhaust IP limit from an IP
$authIp = '10.0.0.50';
$userId = 'user-12345';

for ($i = 1; $i <= 5; $i++) {
    $test("Authenticated request $i", 'GET', '/api/profile', ['X-User-Id' => $userId], $authIp);
}

echo "\n=== Test 5: API Key Based Limiting ===\n\n";

$apiKey = 'key-abc123';
for ($i = 1; $i <= 5; $i++) {
    $test("API key request $i", 'GET', '/api/data', ['X-API-Key' => $apiKey], '10.0.0.60');
}

echo "\n=== Diagnostics ===\n";
$counters = $config->getDiagnosticsCounters();
echo "Throttled requests: " . ($counters['throttle_exceeded']['total'] ?? 0) . "\n";
echo "Breakdown by rule:\n";
foreach ($counters['throttle_exceeded']['by_rule'] ?? [] as $rule => $count) {
    echo "  - $rule: $count\n";
}

echo "\n=== Example Complete ===\n";
