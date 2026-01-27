<?php

/**
 * Example 02: Brute Force Protection
 *
 * This example demonstrates how to protect against brute force attacks using:
 * - Fail2Ban-style IP blocking after repeated failures
 * - Throttling for rate limiting login attempts
 * - Custom failure detection via headers or response inspection
 *
 * Run: php examples/02-brute-force-protection.php
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

echo "=== Brute Force Protection Example ===\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache);

// -----------------------------------------------------------------------------
// Strategy 1: Fail2Ban - Ban IP after X failed login attempts
// -----------------------------------------------------------------------------
// This is the most effective protection against brute force attacks.
// After 5 failed login attempts within 5 minutes, the IP is banned for 1 hour.

$config->fail2ban(
    name: 'login-failures',
    threshold: 5,           // Number of failures before ban
    period: 300,            // Time window in seconds (5 minutes)
    ban: 3600,              // Ban duration in seconds (1 hour)
    filter: fn(ServerRequestInterface $serverRequest): bool =>
        // Track failed login attempts based on X-Login-Failed header
        // In a real app, your login handler sets this header on failed login
        $serverRequest->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);
echo "1. Fail2Ban configured: 5 failures in 5 min = 1 hour ban\n";

// -----------------------------------------------------------------------------
// Strategy 2: Throttle - Limit login attempts per IP
// -----------------------------------------------------------------------------
// Even before banning, slow down potential attackers.
// Max 10 login attempts per minute per IP.

$config->throttle(
    name: 'login-throttle',
    limit: 10,
    period: 60,
    key: function (ServerRequestInterface $serverRequest): ?string {
        // Only apply to login endpoint
        if ($serverRequest->getUri()->getPath() === '/login') {
            return $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;
        }

        return null; // Skip for other endpoints
    }
);
echo "2. Login throttle configured: 10 attempts/min per IP\n";

// -----------------------------------------------------------------------------
// Strategy 3: Account-based throttling
// -----------------------------------------------------------------------------
// Also throttle per username to prevent credential stuffing attacks.

$config->throttle(
    name: 'account-throttle',
    limit: 5,
    period: 60,
    key: function (ServerRequestInterface $serverRequest): ?string {
        // Only apply to login endpoint
        if ($serverRequest->getUri()->getPath() === '/login' && $serverRequest->getMethod() === 'POST') {
            // Extract username from the request (in real app, parse body)
            return in_array($serverRequest->getHeaderLine('X-Username'), ['', '0'], true) ? null : $serverRequest->getHeaderLine('X-Username');
        }

        return null;
    }
);
echo "3. Account throttle configured: 5 attempts/min per username\n\n";

// =============================================================================
// SIMULATION
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

// Simulated login handler
$handler = new class implements RequestHandlerInterface {
    private int $attemptCount = 0;

    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        ++$this->attemptCount;
        $path = $serverRequest->getUri()->getPath();

        if ($path === '/login') {
            // Simulate: first 4 attempts fail, then succeed
            $username = $serverRequest->getHeaderLine('X-Username');
            if ($this->attemptCount < 5) {
                return new Response(401, [
                    'Content-Type' => 'application/json',
                    'X-Login-Failed' => '1',  // Signal failure to firewall
                ], json_encode(['error' => 'Invalid credentials'], JSON_THROW_ON_ERROR));
            }

            return new Response(200, ['Content-Type' => 'application/json'],
                json_encode(['success' => true, 'user' => $username], JSON_THROW_ON_ERROR));
        }

        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

// Helper function
$testRequest = function (string $desc, string $path, array $headers = [], string $ip = '192.168.1.50') use ($middleware, $handler): int {
    $request = new ServerRequest('POST', $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);
    $status = $response->getStatusCode();
    $banned = $response->getHeaderLine('X-Phirewall') === 'blocked';
    $throttled = $status === 429;

    echo sprintf("  %-50s => %d", $desc, $status);
    if ($banned) {
        echo " [BANNED]";
    }

    if ($throttled) {
        $retry = $response->getHeaderLine('Retry-After');
        echo sprintf(' [THROTTLED, retry after %ss]', $retry);
    }

    echo "\n";

    return $status;
};

echo "=== Test 1: Fail2Ban Triggering ===\n";
echo "Simulating failed login attempts from attacker IP...\n\n";

$attackerIp = '10.0.0.100';

// First 5 attempts with failed logins (X-Login-Failed: 1)
for ($i = 1; $i <= 6; ++$i) {
    $testRequest(
        sprintf('Login attempt %d (will fail)', $i),
        '/login',
        ['X-Username' => 'admin', 'X-Login-Failed' => '1'],
        $attackerIp
    );
}

echo "\n";

// The IP should now be banned - test it
echo "After 5 failures, trying again...\n";
$testRequest(
    "Login attempt 7 (should be banned)",
    '/login',
    ['X-Username' => 'admin'],
    $attackerIp
);

echo "\n=== Test 2: Legitimate User from Different IP ===\n";
$legitIp = '10.0.0.200';

// Legitimate user can still try from different IP
for ($i = 1; $i <= 3; ++$i) {
    $testRequest(
        'Legitimate user attempt ' . $i,
        '/login',
        ['X-Username' => 'user123'],
        $legitIp
    );
}

echo "\n=== Test 3: Rate Limiting (Throttle) ===\n";
echo "Rapid requests to /login endpoint...\n\n";

$rapidIp = '10.0.0.300';
for ($i = 1; $i <= 12; ++$i) {
    $testRequest(
        'Rapid request ' . $i,
        '/login',
        ['X-Username' => 'testuser'],
        $rapidIp
    );
}

echo "\n=== Diagnostics ===\n";
$counters = $config->getDiagnosticsCounters();
echo "Banned by Fail2Ban: " . ($counters['fail2ban_banned']['total'] ?? 0) . "\n";
echo "Throttled: " . ($counters['throttle_exceeded']['total'] ?? 0) . "\n";
echo "Passed: " . ($counters['passed']['total'] ?? 0) . "\n";

echo "\n=== Example Complete ===\n";
