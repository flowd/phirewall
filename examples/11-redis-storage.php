<?php

/**
 * Example 11: Redis Storage Backend
 *
 * This example demonstrates how to use Redis as the storage backend for
 * Phirewall counters and bans. Redis is recommended for production deployments
 * with multiple application servers.
 *
 * Features shown:
 * - Redis cache backend setup
 * - Key prefixing for isolation
 * - Automatic TTL management
 * - Multi-server rate limiting
 *
 * Required dependency: predis/predis
 *   composer require predis/predis
 *
 * Run: php examples/11-redis-storage.php
 *
 * Environment:
 *   REDIS_URL=redis://localhost:6379/0 (optional, defaults to localhost)
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Redis Storage Backend Example ===\n\n";

// =============================================================================
// PREDIS CHECK
// =============================================================================

if (!class_exists(\Predis\Client::class)) {
    echo "Predis is not installed.\n";
    echo "Install with: composer require predis/predis\n\n";
    echo "This example requires Redis. Exiting.\n";
    exit(0);
}

// =============================================================================
// REDIS CONNECTION
// =============================================================================

$redisUrl = getenv('REDIS_URL') ?: 'redis://localhost:6379/0';
echo sprintf('Connecting to Redis: %s%s', $redisUrl, PHP_EOL);

try {
    $redisClient = new \Predis\Client($redisUrl);

    // Verify connection
    $pong = (string) $redisClient->ping();
    if (stripos($pong, 'PONG') === false) {
        throw new RuntimeException("Redis did not respond with PONG");
    }

    echo "Redis connection successful\n\n";
} catch (\Throwable $throwable) {
    echo "Failed to connect to Redis: " . $throwable->getMessage() . "\n";
    echo "Make sure Redis is running and REDIS_URL is set correctly.\n";
    exit(1);
}

// =============================================================================
// CACHE SETUP
// =============================================================================

// Use a unique prefix for this example to avoid conflicts
$keyPrefix = 'phirewall:example:' . bin2hex(random_bytes(4)) . ':';
$cache = new RedisCache($redisClient, $keyPrefix);

echo "Redis cache configured with prefix: {$keyPrefix}\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$config = new Config($cache);
$config->enableRateLimitHeaders();
$config->enableResponseHeaders();

// Strict throttle to demonstrate Redis storage
$config->throttles->add(
    name: 'ip-limit',
    limit: 3,           // Only 3 requests
    period: 30,         // Per 30 seconds
    key: KeyExtractors::ip()
);
echo "Throttle rule: 3 requests per 30 seconds per IP\n";

// Fail2Ban for demonstration
$config->fail2ban->add(
    name: 'abuse',
    threshold: 2,       // 2 blocked requests
    period: 60,         // In 1 minute
    ban: 300,           // 5 minute ban
    filter: fn($req): bool => $req->getHeaderLine('X-Abuse') === '1',
    key: KeyExtractors::ip()
);
echo "Fail2Ban rule: 2 abuse markers = 5 minute ban\n\n";

// =============================================================================
// MIDDLEWARE & HANDLER
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"status":"ok"}');
    }
};

// Helper function
$testRequest = function (string $desc, string $ip, array $headers = []) use ($middleware, $handler): void {
    $request = new ServerRequest('GET', '/api/data', $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);

    $status = $response->getStatusCode();
    $remaining = $response->getHeaderLine('X-RateLimit-Remaining');
    $phirewall = $response->getHeaderLine('X-Phirewall');

    echo sprintf("  %-40s => %d", $desc, $status);
    if ($remaining !== '') {
        echo sprintf(' [remaining: %s]', $remaining);
    }

    if ($phirewall === 'blocked') {
        $rule = $response->getHeaderLine('X-Phirewall-Matched');
        echo sprintf(' [blocked: %s]', $rule);
    }

    echo "\n";
};

// =============================================================================
// SIMULATION
// =============================================================================

echo "=== Request Simulation ===\n\n";

echo "Test 1: Rate limiting with Redis storage\n";
$testIp = '192.168.1.100';
for ($i = 1; $i <= 5; ++$i) {
    $testRequest(sprintf('Request %d from %s', $i, $testIp), $testIp);
}

echo "\n";

echo "Test 2: Different IP has separate quota\n";
$testIp2 = '192.168.1.200';
for ($i = 1; $i <= 3; ++$i) {
    $testRequest(sprintf('Request %d from %s', $i, $testIp2), $testIp2);
}

echo "\n";

echo "Test 3: Fail2Ban with Redis storage\n";
$abuserIp = '10.0.0.50';
for ($i = 1; $i <= 4; ++$i) {
    $testRequest(sprintf('Abuse attempt %d from %s', $i, $abuserIp), $abuserIp, ['X-Abuse' => '1']);
}

echo "\n";

// =============================================================================
// VERIFY REDIS KEYS
// =============================================================================

echo "=== Redis Keys Created ===\n\n";

$keys = $redisClient->keys($keyPrefix . '*');
echo "Keys stored in Redis:\n";
foreach ($keys as $key) {
    $ttl = $redisClient->ttl($key);
    $type = $redisClient->type($key);
    echo sprintf("  %s (type: %s, TTL: %ds)\n", $key, $type, $ttl);
}

echo "\n";

// =============================================================================
// CLEANUP
// =============================================================================

echo "=== Cleanup ===\n\n";

// Delete all keys created by this example
foreach ($keys as $key) {
    $redisClient->del($key);
}

echo "Deleted " . count($keys) . " keys from Redis\n";

// =============================================================================
// PRODUCTION TIPS
// =============================================================================

echo "\n=== Production Tips ===\n\n";

echo "1. Key Prefix Strategy:\n";
echo "   - Use environment-specific prefixes: phirewall:prod:, phirewall:staging:\n";
echo "   - Include application name for multi-app Redis: myapp:phirewall:\n\n";

echo "2. Redis Configuration:\n";
echo "   - Use Redis Cluster for high availability\n";
echo "   - Set appropriate maxmemory-policy (allkeys-lru recommended)\n";
echo "   - Monitor memory usage as keys accumulate\n\n";

echo "3. Connection Pooling:\n";
echo "   - Reuse the Predis client across requests\n";
echo "   - Consider using persistent connections\n\n";

echo "4. Failover Strategy:\n";
echo "   - Wrap RedisCache in try/catch for graceful degradation\n";
echo "   - Fall back to InMemoryCache if Redis is unavailable\n\n";

echo "=== Example Complete ===\n";
