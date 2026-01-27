<?php

/**
 * Example 06: Scanner and Bot Detection
 *
 * This example demonstrates how to detect and block:
 * - Known vulnerability scanners (sqlmap, nikto, nmap, etc.)
 * - Malicious bots
 * - Common scanner path probes
 * - Empty or suspicious User-Agents
 *
 * Run: php examples/06-bot-detection.php
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

echo "=== Scanner and Bot Detection Example ===\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache);

// -----------------------------------------------------------------------------
// Rule 1: Block known vulnerability scanners by User-Agent
// -----------------------------------------------------------------------------

$scannerUserAgents = [
    'sqlmap',           // SQL injection scanner
    'nikto',            // Web server scanner
    'nmap',             // Network scanner
    'masscan',          // Port scanner
    'burp',             // Burp Suite
    'dirbuster',        // Directory brute-forcer
    'gobuster',         // Directory brute-forcer
    'wfuzz',            // Web fuzzer
    'ffuf',             // Fast web fuzzer
    'nuclei',           // Vulnerability scanner
    'zap',              // OWASP ZAP
    'acunetix',         // Commercial scanner
    'nessus',           // Vulnerability scanner
    'openvas',          // Vulnerability scanner
    'w3af',             // Web application attack framework
    'arachni',          // Web scanner
    'skipfish',         // Google's scanner
    'whatweb',          // Web fingerprinting
    'wpscan',           // WordPress scanner
    'joomscan',         // Joomla scanner
    'droopescan',       // CMS scanner
];

$config->blocklist('scanner-ua', function (ServerRequestInterface $serverRequest) use ($scannerUserAgents): bool {
    $ua = strtolower($serverRequest->getHeaderLine('User-Agent'));

    if ($ua === '') {
        return false;  // Handled by separate rule
    }

    foreach ($scannerUserAgents as $scannerUserAgent) {
        if (str_contains($ua, $scannerUserAgent)) {
            return true;
        }
    }

    return false;
});
echo "1. Scanner User-Agent blocklist configured\n";

// -----------------------------------------------------------------------------
// Rule 2: Block empty User-Agents (often bots)
// -----------------------------------------------------------------------------

$config->blocklist('empty-ua', function (ServerRequestInterface $serverRequest): bool {
    $ua = $serverRequest->getHeaderLine('User-Agent');
    return $ua === '' || trim($ua) === '';
});
echo "2. Empty User-Agent blocklist configured\n";

// -----------------------------------------------------------------------------
// Rule 3: Block common scanner path probes
// -----------------------------------------------------------------------------

$scannerPaths = [
    // WordPress
    '/wp-admin',
    '/wp-login.php',
    '/wp-config.php',
    '/wp-content/plugins',
    '/xmlrpc.php',

    // phpMyAdmin
    '/phpmyadmin',
    '/pma',
    '/mysql',
    '/mysqladmin',
    '/myadmin',
    '/dbadmin',

    // Config/sensitive files
    '/.env',
    '/.git',
    '/.svn',
    '/.htaccess',
    '/.htpasswd',
    '/config.php',
    '/configuration.php',
    '/settings.php',
    '/config.inc.php',
    '/wp-config.php.bak',

    // Debug/info
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    '/debug.php',
    '/server-status',
    '/server-info',

    // Common CMS
    '/administrator',
    '/admin.php',
    '/admin/login',
    '/user/login',

    // ASP.NET
    '/elmah.axd',
    '/trace.axd',
    '/web.config',

    // Backup files
    '/backup',
    '/backups',
    '/db.sql',
    '/dump.sql',
    '/database.sql',
    '/.sql',

    // Shell uploads
    '/shell.php',
    '/c99.php',
    '/r57.php',
    '/webshell',
];

$config->blocklist('scanner-paths', function (ServerRequestInterface $serverRequest) use ($scannerPaths): bool {
    $path = strtolower($serverRequest->getUri()->getPath());

    foreach ($scannerPaths as $scannerPath) {
        if (str_starts_with($path, $scannerPath) || $path === $scannerPath) {
            return true;
        }
    }

    // Also check for backup file extensions
    return (bool) preg_match('/\.(bak|backup|old|orig|save|swp|~)$/i', $path);
});
echo "3. Scanner path blocklist configured (" . count($scannerPaths) . " paths)\n";

// -----------------------------------------------------------------------------
// Rule 4: Block suspicious request patterns
// -----------------------------------------------------------------------------

$config->blocklist('suspicious-patterns', function (ServerRequestInterface $serverRequest): bool {
    $uri = $serverRequest->getUri()->getPath() . '?' . $serverRequest->getUri()->getQuery();

    $suspiciousPatterns = [
        // Shell commands
        '/etc/passwd',
        '/etc/shadow',
        '/proc/self',
        '/windows/system32',
        'cmd.exe',
        'powershell',

        // PHP wrappers
        'php://input',
        'php://filter',
        'expect://',
        'data://',

        // Path traversal (basic)
        '../../../',
        '..%2f..%2f',
        '....//....//​',
    ];

    foreach ($suspiciousPatterns as $suspiciouPattern) {
        if (str_contains(strtolower($uri), $suspiciouPattern)) {
            return true;
        }
    }

    return false;
});
echo "4. Suspicious pattern blocklist configured\n";

// -----------------------------------------------------------------------------
// Rule 5: Fail2Ban for persistent scanners
// -----------------------------------------------------------------------------

$config->fail2ban(
    name: 'persistent-scanner',
    threshold: 5,       // 5 blocked requests
    period: 60,         // In 1 minute
    ban: 86400,         // 24 hour ban
    filter: fn(ServerRequestInterface $serverRequest): bool =>
        // This filter matches requests that hit our blocklist rules
        // In practice, you'd track this via events
        $serverRequest->getHeaderLine('X-Scanner-Detected') === '1',
    key: KeyExtractors::ip()
);
echo "5. Fail2Ban for persistent scanners configured\n";

// -----------------------------------------------------------------------------
// Rate limiting for rapid requests (bot behavior)
// -----------------------------------------------------------------------------

$config->throttle(
    name: 'rapid-requests',
    limit: 30,          // 30 requests
    period: 10,         // In 10 seconds
    key: KeyExtractors::ip()
);
echo "6. Rapid request throttling configured (30/10s)\n\n";

// =============================================================================
// SIMULATION
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

// Helper function
$testRequest = function (string $desc, string $path, array $headers = [], string $ip = '10.0.0.1') use ($middleware, $handler): void {
    $request = new ServerRequest('GET', $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);

    $status = $response->getStatusCode();
    $result = $status === 200 ? 'ALLOW' : 'BLOCK';
    $rule = in_array($response->getHeaderLine('X-Phirewall-Matched'), ['', '0'], true) ? '-' : $response->getHeaderLine('X-Phirewall-Matched');

    echo sprintf("  [%s] %-50s (rule: %s)\n", $result, $desc, $rule);
};

echo "=== Testing Scanner Detection ===\n\n";

echo "Test 1: Normal browser requests\n";
$testRequest('Chrome user', '/api/users', ['User-Agent' => 'Mozilla/5.0 Chrome/120.0']);
$testRequest('Firefox user', '/api/products', ['User-Agent' => 'Mozilla/5.0 Firefox/121.0']);
$testRequest('Safari user', '/index.html', ['User-Agent' => 'Mozilla/5.0 Safari/17.0']);
echo "\n";

echo "Test 2: Vulnerability scanner User-Agents\n";
$testRequest('sqlmap scanner', '/api/users', ['User-Agent' => 'sqlmap/1.7']);
$testRequest('nikto scanner', '/', ['User-Agent' => 'Nikto/2.5']);
$testRequest('nmap scanner', '/', ['User-Agent' => 'Nmap Scripting Engine']);
$testRequest('burp suite', '/api/', ['User-Agent' => 'Burp Suite']);
$testRequest('dirbuster', '/admin', ['User-Agent' => 'DirBuster/1.0']);
$testRequest('wfuzz', '/api/', ['User-Agent' => 'Wfuzz/3.1']);
echo "\n";

echo "Test 3: Empty User-Agent\n";
$testRequest('No User-Agent', '/api/users', []);
$testRequest('Empty User-Agent', '/api/users', ['User-Agent' => '']);
$testRequest('Whitespace User-Agent', '/api/users', ['User-Agent' => '   ']);
echo "\n";

echo "Test 4: Scanner path probes\n";
$testRequest('WordPress admin', '/wp-admin/', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('WordPress login', '/wp-login.php', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('phpMyAdmin', '/phpmyadmin/', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('.env file', '/.env', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('.git folder', '/.git/HEAD', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('phpinfo', '/phpinfo.php', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('backup file', '/db.sql', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('config backup', '/config.php.bak', ['User-Agent' => 'Mozilla/5.0']);
echo "\n";

echo "Test 5: Suspicious patterns\n";
$testRequest('Path traversal', '/../../../etc/passwd', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('PHP wrapper', '/page?file=php://filter/convert.base64-encode', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('Windows path', '/page?cmd=c:\\windows\\system32\\cmd.exe', ['User-Agent' => 'Mozilla/5.0']);
echo "\n";

echo "Test 6: Rapid requests (bot behavior)\n";
$ip = '192.168.1.100';
for ($i = 1; $i <= 35; ++$i) {
    if ($i <= 3 || $i >= 29) {
        $testRequest(sprintf('Rapid request %s from %s', $i, $ip), '/api/data', ['User-Agent' => 'Mozilla/5.0'], $ip);
    } elseif ($i === 4) {
        echo "  ... (requests 4-28 omitted) ...\n";
    }
}

echo "\n";

echo "=== Diagnostics ===\n";
$counters = $config->getDiagnosticsCounters();
echo "Blocked by blocklist: " . ($counters['blocklisted']['total'] ?? 0) . "\n";
foreach ($counters['blocklisted']['by_rule'] ?? [] as $rule => $count) {
    echo sprintf('  - %s: %d%s', $rule, $count, PHP_EOL);
}

echo "Throttled: " . ($counters['throttle_exceeded']['total'] ?? 0) . "\n";
echo "Allowed: " . ($counters['passed']['total'] ?? 0) . "\n";

echo "\n=== Example Complete ===\n";
