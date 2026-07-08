<?php

/**
 * Example 02: Brute Force Protection
 *
 * This example demonstrates how to protect against brute force attacks using:
 * - Allow2Ban with a filter: count login attempts, ban the IP after too many
 *   within a window (matching requests pass until the threshold)
 * - Throttling for rate limiting the login endpoint
 *
 * Why Allow2Ban and not Fail2Ban here? Fail2Ban blocks EVERY filter match on the
 * spot, which is right for unambiguously malicious traffic (scanner paths) but
 * wrong for a login endpoint, where an attempt is still a legitimate request
 * that should be allowed a few retries. Allow2Ban with a filter counts the
 * attempts and only bans once they cross the threshold.
 *
 * A request filter cannot tell a failed login from a successful one (the result
 * only exists after the handler ran), so the filter counts every attempt; pick
 * the threshold generously. To count only actual failures, report them from the
 * handler with RequestContext::recordHit() instead, see example 27.
 *
 * Run: php examples/02-brute-force-protection.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
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
$diagnostics = new DiagnosticsCounters();
$config = new Config($cache, new DiagnosticsDispatcher($diagnostics));
$config->enableResponseHeaders();

// -----------------------------------------------------------------------------
// Strategy 1: Allow2Ban with a filter - ban IP after too many login attempts
// -----------------------------------------------------------------------------
// Count only requests the filter matches (POSTs to the login endpoint).
// Attempts 1-4 pass through; the 5th within the window bans the IP for 1 hour.
// Page views and other endpoints are never counted.

$config->allow2ban->add(
    name: 'login-brute-force',
    threshold: 5,           // matching requests before the ban trips (>= semantic)
    period: 300,            // time window in seconds (5 minutes)
    banSeconds: 3600,       // ban duration in seconds (1 hour)
    key: fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR'] ?? '',
    filter: fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getMethod() === 'POST'
        && $serverRequest->getUri()->getPath() === '/login',
);
echo "1. Allow2Ban configured: 5 login attempts in 5 min = 1 hour ban (matching requests pass until then)\n";

// -----------------------------------------------------------------------------
// Strategy 2: Throttle - Limit login attempts per IP
// -----------------------------------------------------------------------------
// Even before banning, slow down potential attackers.
// Max 10 login attempts per minute per IP.

$config->throttles->add(
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
// Also throttle per username to prevent credential stuffing attacks. The limit
// sits above the allow2ban threshold, so a hammered account still throttles
// even when the attempts come from many different (not yet banned) IPs.

$config->throttles->add(
    name: 'account-throttle',
    limit: 8,
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
echo "3. Account throttle configured: 8 attempts/min per username\n\n";

// =============================================================================
// SIMULATION
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

// Simulated login handler. The "admin" account here always fails (simulated
// credential-stuffing attack); any other username succeeds. A real handler
// would validate against a credential store.
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $path = $serverRequest->getUri()->getPath();

        if ($path === '/login' && $serverRequest->getMethod() === 'POST') {
            $failed = $serverRequest->getHeaderLine('X-Username') === 'admin';

            if ($failed) {
                return new Response(401, [
                    'Content-Type' => 'application/json',
                ], json_encode(['error' => 'Invalid credentials'], JSON_THROW_ON_ERROR));
            }

            return new Response(200, ['Content-Type' => 'application/json'],
                json_encode(['success' => true], JSON_THROW_ON_ERROR));
        }

        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

// Helper function
$testRequest = function (string $desc, string $path, array $headers = [], string $ip = '192.168.1.50', string $method = 'POST') use ($middleware, $handler): int {
    $request = new ServerRequest($method, $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);
    $status = $response->getStatusCode();
    $banned = $status === 403;
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

echo "=== Test 1: Allow2Ban Triggering ===\n";
echo "Simulating login attempts from attacker IP...\n\n";

$attackerIp = '10.0.0.100';

// Every POST to /login counts; the 5th within the window bans the IP.
for ($i = 1; $i <= 6; ++$i) {
    $testRequest(
        sprintf('Login attempt %d (will fail)', $i),
        '/login',
        ['X-Username' => 'admin'],
        $attackerIp
    );
}

echo "\n";

// The IP should now be banned - test it
echo "After 5 attempts, trying again...\n";
$testRequest(
    "Login attempt 7 (should be banned)",
    '/login',
    ['X-Username' => 'admin'],
    $attackerIp
);

echo "\n=== Test 2: Legitimate User from Different IP ===\n";
$legitIp = '10.0.0.200';

// The legitimate user's attempts count too, but stay well below the threshold.
for ($i = 1; $i <= 3; ++$i) {
    $testRequest(
        'Legitimate user attempt ' . $i,
        '/login',
        ['X-Username' => 'user123'],
        $legitIp
    );
}

echo "\n=== Test 3: Rate Limiting (Throttle) ===\n";
echo "Rapidly reloading the login page (GET does not count as an attempt)...\n\n";

$rapidIp = '10.0.0.30';
for ($i = 1; $i <= 12; ++$i) {
    $testRequest(
        'Rapid request ' . $i,
        '/login',
        [],
        $rapidIp,
        'GET'
    );
}

echo "\n=== Diagnostics ===\n";
$counters = $diagnostics->all();
echo "Banned by Allow2Ban: " . ($counters['allow2ban_banned']['total'] ?? 0) . "\n";
echo "Throttled: " . ($counters['throttle_exceeded']['total'] ?? 0) . "\n";
echo "Passed: " . ($counters['passed']['total'] ?? 0) . "\n";

echo "\n=== Example Complete ===\n";
