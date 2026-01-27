<?php

/**
 * Example 08: Comprehensive Production-Ready Protection
 *
 * This example combines all protection strategies into a production-ready
 * configuration that defends against multiple attack vectors:
 *
 * - SQL Injection (OWASP rules)
 * - XSS Attacks (OWASP rules)
 * - Brute Force (Fail2Ban + throttling)
 * - DDoS/Rate Abuse (tiered rate limiting)
 * - Scanner Detection (User-Agent + path blocking)
 * - Path Traversal (pattern detection)
 *
 * Run: php examples/08-comprehensive-protection.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Comprehensive Production-Ready Protection ===\n\n";

// =============================================================================
// EVENT DISPATCHER (Logging)
// =============================================================================

$dispatcher = new class implements EventDispatcherInterface {
    private array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;
        return $event;
    }

    public function getEvents(): array
    {
        return $this->events;
    }

    public function clear(): void
    {
        $this->events = [];
    }
};

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache, $dispatcher);
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();

// Trusted proxy configuration (adjust for your infrastructure)
$proxyResolver = new TrustedProxyResolver([
    '127.0.0.1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);

echo "Configuration:\n";
echo "  Key prefix: prod\n";
echo "  Rate limit headers: enabled\n\n";

// =============================================================================
// LAYER 1: SAFELISTS (Bypass all checks)
// =============================================================================

echo "Layer 1: Safelists\n";

$config->safelist('health', fn($req) => $req->getUri()->getPath() === '/health');
echo "  - /health endpoint\n";

$config->safelist('metrics', fn($req) => $req->getUri()->getPath() === '/metrics');
echo "  - /metrics endpoint\n";

$config->safelist('internal-ips', function ($req) use ($proxyResolver): bool {
    $ip = $proxyResolver->resolve($req);
    if ($ip === null) {
        return false;
    }
    // Allow localhost and specific internal range
    return $ip === '127.0.0.1' || str_starts_with($ip, '192.168.10.');
});
echo "  - Internal IP range (192.168.10.0/24)\n\n";

// =============================================================================
// LAYER 2: BLOCKLISTS (Immediate denial)
// =============================================================================

echo "Layer 2: Blocklists\n";

// Scanner User-Agents
$scanners = ['sqlmap', 'nikto', 'nmap', 'burp', 'dirbuster', 'wfuzz', 'nuclei'];
$config->blocklist('scanner-ua', function ($req) use ($scanners): bool {
    $ua = strtolower($req->getHeaderLine('User-Agent'));
    foreach ($scanners as $scanner) {
        if (str_contains($ua, $scanner)) {
            return true;
        }
    }
    return false;
});
echo "  - Scanner User-Agents (" . count($scanners) . " patterns)\n";

// Scanner paths
$blockedPaths = ['/wp-admin', '/phpmyadmin', '/.env', '/.git', '/phpinfo.php'];
$config->blocklist('scanner-paths', function ($req) use ($blockedPaths): bool {
    $path = strtolower($req->getUri()->getPath());
    foreach ($blockedPaths as $blocked) {
        if (str_starts_with($path, $blocked)) {
            return true;
        }
    }
    return false;
});
echo "  - Scanner paths (" . count($blockedPaths) . " patterns)\n";

// Path traversal
$config->blocklist('path-traversal', function ($req): bool {
    $input = urldecode($req->getUri()->getPath() . '?' . $req->getUri()->getQuery());
    return preg_match('~\.\.[\\\\/]~', $input) === 1;
});
echo "  - Path traversal patterns\n\n";

// =============================================================================
// LAYER 3: OWASP RULES (SQL Injection, XSS, etc.)
// =============================================================================

echo "Layer 3: OWASP Rules\n";

$owaspRules = <<<'CRS'
# SQL Injection
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:'SQLi: UNION SELECT'"
SecRule ARGS "@rx (?i)('\s*(or|and)\s*'|'\s*=\s*')" "id:942110,phase:2,deny,msg:'SQLi: Boolean'"
SecRule ARGS "@rx (--|/\*|\*/)" "id:942120,phase:2,deny,msg:'SQLi: Comment'"
SecRule ARGS "@rx (?i);\s*(drop|delete|insert|update)\b" "id:942130,phase:2,deny,msg:'SQLi: Stacked'"

# XSS
SecRule ARGS "@rx (?i)<script[^>]*>" "id:941100,phase:2,deny,msg:'XSS: Script tag'"
SecRule ARGS "@rx (?i)\bon(load|error|click|mouseover)\s*=" "id:941110,phase:2,deny,msg:'XSS: Event handler'"
SecRule ARGS "@rx (?i)javascript\s*:" "id:941120,phase:2,deny,msg:'XSS: JS protocol'"

# PHP Injection
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec)\s*\(" "id:933100,phase:2,deny,msg:'PHP: Code injection'"
SecRule ARGS "@rx (?i)(base64_decode|gzinflate)\s*\(" "id:933110,phase:2,deny,msg:'PHP: Obfuscation'"
CRS;

$coreRuleSet = SecRuleLoader::fromString($owaspRules);
$config->owaspBlocklist('owasp', $coreRuleSet);
echo "  - SQL Injection rules (4)\n";
echo "  - XSS rules (3)\n";
echo "  - PHP Injection rules (2)\n\n";

// =============================================================================
// LAYER 4: FAIL2BAN (Brute force protection)
// =============================================================================

echo "Layer 4: Fail2Ban\n";

// Login brute force
$config->fail2ban('login-brute',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::clientIp($proxyResolver)
);
echo "  - Login: 5 failures in 5min = 1 hour ban\n";

// API abuse
$config->fail2ban('api-abuse',
    threshold: 10,
    period: 60,
    ban: 1800,
    filter: fn($req) => $req->getHeaderLine('X-API-Error') === '1',
    key: KeyExtractors::clientIp($proxyResolver)
);
echo "  - API: 10 errors in 1min = 30 min ban\n\n";

// =============================================================================
// LAYER 5: THROTTLING (Rate limiting)
// =============================================================================

echo "Layer 5: Throttling\n";

// Global limit
$config->throttle('global', limit: 200, period: 60, key: KeyExtractors::clientIp($proxyResolver));
echo "  - Global: 200/min per IP\n";

// Write operations
$config->throttle('write-ops', limit: 50, period: 60, key: function ($req) use ($proxyResolver): ?string {
    if (in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
        return $proxyResolver->resolve($req);
    }
    return null;
});
echo "  - Write ops: 50/min per IP\n";

// Login endpoint
$config->throttle('login', limit: 10, period: 60, key: function ($req) use ($proxyResolver): ?string {
    if ($req->getUri()->getPath() === '/login') {
        return $proxyResolver->resolve($req);
    }
    return null;
});
echo "  - Login: 10/min per IP\n";

// Authenticated users (higher limit)
$config->throttle('user', limit: 1000, period: 60, key: KeyExtractors::header('X-User-Id'));
echo "  - Authenticated: 1000/min per user\n";

// Burst detection
$config->throttle('burst', limit: 30, period: 5, key: KeyExtractors::clientIp($proxyResolver));
echo "  - Burst: 30/5s per IP\n\n";

// =============================================================================
// CUSTOM RESPONSES
// =============================================================================

$config->blocklistedResponse(function (string $rule, string $type, $req): ResponseInterface {
    return new Response(403, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'Forbidden',
        'message' => 'Your request has been blocked by our security system.',
        'code' => 'SECURITY_BLOCK',
    ], JSON_THROW_ON_ERROR));
});

$config->throttledResponse(function (string $rule, int $retryAfter, $req): ResponseInterface {
    return new Response(429, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'Too Many Requests',
        'message' => 'Rate limit exceeded. Please try again later.',
        'retry_after' => $retryAfter,
    ], JSON_THROW_ON_ERROR));
});

// =============================================================================
// SIMULATION
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"status":"ok"}');
    }
};

$test = function (string $desc, string $method, string $path, array $headers = [], string $ip = '203.0.113.1') use ($middleware, $handler): int {
    $headers = array_merge(['User-Agent' => 'Mozilla/5.0'], $headers);
    $request = new ServerRequest($method, $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);
    return $response->getStatusCode();
};

echo "=== Attack Simulation ===\n\n";

// Test matrix
$tests = [
    ['Safe request', 'GET', '/api/users', [], '203.0.113.1', 200],
    ['Health check (safelisted)', 'GET', '/health', [], '203.0.113.1', 200],

    // Scanners
    ['SQLMap scanner', 'GET', '/api', ['User-Agent' => 'sqlmap/1.7'], '1.1.1.1', 403],
    ['Nikto scanner', 'GET', '/', ['User-Agent' => 'Nikto/2.5'], '1.1.1.2', 403],

    // Scanner paths
    ['WordPress probe', 'GET', '/wp-admin/', [], '1.1.1.3', 403],
    ['.env access', 'GET', '/.env', [], '1.1.1.4', 403],

    // SQL Injection
    ['SQLi UNION', 'GET', '/api?id=1+UNION+SELECT', [], '1.1.1.5', 403],
    ['SQLi Boolean', 'GET', "/api?user=admin'OR'1'='1", [], '1.1.1.6', 403],

    // XSS
    ['XSS Script', 'GET', '/api?q=<script>alert(1)', [], '1.1.1.7', 403],
    ['XSS Event', 'GET', '/api?q=<img+onerror=alert(1)>', [], '1.1.1.8', 403],

    // Path traversal
    ['Path traversal', 'GET', '/files/../../../etc/passwd', [], '1.1.1.9', 403],
];

$passed = 0;
$failed = 0;

foreach ($tests as [$desc, $method, $path, $headers, $ip, $expected]) {
    $actual = $test($desc, $method, $path, $headers, $ip);
    $status = $actual === $expected ? 'PASS' : 'FAIL';

    if ($actual === $expected) {
        $passed++;
    } else {
        $failed++;
    }

    echo sprintf("[%s] %-25s => %d (expected %d)\n", $status, $desc, $actual, $expected);
}

echo "\n";

// Fail2Ban test
echo "Fail2Ban Test (simulating login brute force):\n";
$bruteForceIp = '198.51.100.1';
for ($i = 1; $i <= 7; $i++) {
    // First 5 requests are "failed logins" (filter matches), then 2 normal requests
    $headers = $i <= 5 ? ['X-Login-Failed' => '1'] : [];
    $status = $test("Login attempt $i", 'POST', '/login', $headers, $bruteForceIp);
    $desc = $i <= 5 ? '(failed login)' : '(normal request, should be banned)';
    echo sprintf("  Attempt %d %s: %d\n", $i, $desc, $status);
}
echo "\n";

// Rate limiting test
echo "Rate Limiting Test (30 rapid requests from single IP):\n";
$ip = '10.20.30.40';
$blocked = 0;
for ($i = 1; $i <= 35; $i++) {
    $status = $test("Request $i", 'GET', '/api/data', [], $ip);
    if ($status === 429) {
        $blocked++;
    }
    if ($i <= 3 || $i >= 30) {
        echo sprintf("  Request %d: %d\n", $i, $status);
    } elseif ($i === 4) {
        echo "  ... (requests 4-29) ...\n";
    }
}
echo "  Blocked by rate limit: $blocked requests\n\n";

// =============================================================================
// RESULTS
// =============================================================================

echo "=== Results ===\n";
echo "Attack tests passed: $passed\n";
echo "Attack tests failed: $failed\n\n";

echo "=== Diagnostics Summary ===\n";
$counters = $config->getDiagnosticsCounters();

$categories = [
    'safelisted' => 'Safelisted (bypassed)',
    'blocklisted' => 'Blocked by blocklist/OWASP',
    'throttle_exceeded' => 'Throttled (rate limited)',
    'fail2ban_banned' => 'Banned by Fail2Ban',
    'passed' => 'Passed (allowed)',
];

foreach ($categories as $key => $label) {
    $total = $counters[$key]['total'] ?? 0;
    echo sprintf("  %-30s: %d\n", $label, $total);

    // Show breakdown by rule
    foreach ($counters[$key]['by_rule'] ?? [] as $rule => $count) {
        echo sprintf("    - %-25s: %d\n", $rule, $count);
    }
}

echo "\n=== Production Deployment Checklist ===\n";
echo "[ ] Replace InMemoryCache with RedisCache for multi-server\n";
echo "[ ] Configure TrustedProxyResolver with your load balancer IPs\n";
echo "[ ] Adjust rate limits based on expected traffic\n";
echo "[ ] Enable OWASP diagnostics header only in staging\n";
echo "[ ] Set up event dispatcher for logging/alerting\n";
echo "[ ] Test with your application's specific endpoints\n";
echo "[ ] Monitor diagnostics counters in production\n";

echo "\n=== Example Complete ===\n";
