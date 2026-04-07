<?php

/**
 * Example 01: Basic Setup
 *
 * This example demonstrates the minimal configuration needed to use Phirewall.
 *
 * Features shown:
 * - Creating a cache backend
 * - Configuring basic rules (safelist, blocklist, throttle)
 * - Processing requests through the middleware
 *
 * Run: php examples/01-basic-setup.php
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
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Phirewall Basic Setup Example ===\n\n";

// =============================================================================
// STEP 1: Create a cache backend
// =============================================================================
// InMemoryCache is perfect for testing and development.
// For production, use RedisCache or ApcuCache.

$cache = new InMemoryCache();
echo "1. Cache backend created (InMemoryCache)\n";

// =============================================================================
// STEP 2: Create configuration
// =============================================================================

$config = new Config($cache);

// Set a custom key prefix to avoid collisions in shared caches
$config->setKeyPrefix('demo');

// Enable standard rate limit headers (X-RateLimit-*)
$config->enableRateLimitHeaders();

// Enable X-Phirewall, X-Phirewall-Matched, and X-Phirewall-Safelist response headers (opt-in)
$config->enableResponseHeaders();

echo "2. Configuration created with prefix 'demo'\n";

// =============================================================================
// STEP 3: Define rules
// =============================================================================

// SAFELIST: Allow health checks to bypass all rules
$config->safelists->add('health', fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/health');
echo "3a. Safelist rule added: health endpoint\n";

// BLOCKLIST: Block requests to /wp-admin (WordPress scanner probe)
$config->blocklists->add('wp-probe', fn(ServerRequestInterface $serverRequest): bool => str_starts_with($serverRequest->getUri()->getPath(), '/wp-admin'));
echo "3b. Blocklist rule added: WordPress probes\n";

// THROTTLE: Limit to 5 requests per 60 seconds per IP
$config->throttles->add(
    name: 'ip-limit',
    limit: 5,
    period: 60,
    key: KeyExtractors::ip()
);
echo "3c. Throttle rule added: 5 requests/minute per IP\n";

// =============================================================================
// STEP 4: Create middleware
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());
echo "4. Middleware created\n\n";

// =============================================================================
// STEP 5: Simulate requests
// =============================================================================

// Simple handler that returns 200 OK
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "Hello, World!\n");
    }
};

// Helper function to display results
$testRequest = function (string $description, ServerRequest $serverRequest) use ($middleware, $handler): void {
    $response = $middleware->process($serverRequest, $handler);
    $status = $response->getStatusCode();
    $path = $serverRequest->getUri()->getPath();
    $ip = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? 'unknown';

    echo sprintf("  %-40s => %d\n", $description, $status);

    // Show relevant headers
    $headers = ['X-Phirewall', 'X-Phirewall-Matched', 'X-Phirewall-Safelist', 'Retry-After', 'X-RateLimit-Remaining'];
    foreach ($headers as $header) {
        $value = $response->getHeaderLine($header);
        if ($value !== '') {
            echo sprintf("    %s: %s\n", $header, $value);
        }
    }
};

echo "=== Request Simulation ===\n\n";

// Test 1: Health check (safelisted)
echo "Test 1: Health check endpoint (safelisted)\n";
$testRequest(
    'GET /health',
    new ServerRequest('GET', '/health', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.100'])
);
echo "\n";

// Test 2: WordPress probe (blocklisted)
echo "Test 2: WordPress admin probe (blocklisted)\n";
$testRequest(
    'GET /wp-admin/admin.php',
    new ServerRequest('GET', '/wp-admin/admin.php', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.101'])
);
echo "\n";

// Test 3: Normal requests (throttled after 5)
echo "Test 3: Normal requests (5 allowed, then throttled)\n";
$ip = '192.168.1.102';
for ($i = 1; $i <= 7; ++$i) {
    $testRequest(
        sprintf('Request %d from %s', $i, $ip),
        new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => $ip])
    );
}

echo "\n";

// Test 4: Different IP has its own quota
echo "Test 4: Different IP (separate quota)\n";
$testRequest(
    'GET /api/users from 192.168.1.103',
    new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.103'])
);
echo "\n";

echo "=== Example Complete ===\n";
