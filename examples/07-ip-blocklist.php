<?php

/**
 * Example 07: File-Backed IP Blocklist
 *
 * This example demonstrates how to use file-backed blocklists with:
 * - IP address blocking
 * - CIDR range blocking
 * - Path-based blocking
 * - Header-based blocking (User-Agent patterns)
 * - Expiring entries
 *
 * Run: php examples/07-ip-blocklist.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== File-Backed IP Blocklist Example ===\n\n";

// =============================================================================
// SETUP
// =============================================================================

// Create temporary file for the blocklist
$blocklistFile = sys_get_temp_dir() . '/phirewall-blocklist-demo.txt';
echo "Blocklist file: {$blocklistFile}\n\n";

// Clean up any existing file
if (file_exists($blocklistFile)) {
    unlink($blocklistFile);
}

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$diagnostics = new DiagnosticsCounters();
$config = new Config($cache, new DiagnosticsDispatcher($diagnostics));
$config->enableResponseHeaders();

// Create a file pattern backend
$backend = $config->blocklists->filePatternBackend('blocklist', $blocklistFile);
echo "1. File pattern backend created\n";

// Register it as a blocklist
$config->blocklists->fromBackend('dynamic-blocklist', 'blocklist');
echo "2. Blocklist rule registered\n\n";

// =============================================================================
// POPULATE BLOCKLIST
// =============================================================================

echo "=== Populating Blocklist ===\n\n";

// Add specific IP addresses
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '192.168.1.100',
    metadata: ['reason' => 'Malicious activity detected'],
));
echo "Added IP: 192.168.1.100\n";

$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '192.168.1.101',
    expiresAt: time() + 3600,  // Expires in 1 hour
    metadata: ['reason' => 'Temporary ban', 'duration' => '1 hour'],
));
echo "Added IP: 192.168.1.101 (expires in 1 hour)\n";

$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '2001:db8::1',
    metadata: ['reason' => 'IPv6 test'],
));
echo "Added IPv6: 2001:db8::1\n";

// Add CIDR ranges
$backend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '10.0.0.0/8',
    metadata: ['reason' => 'Block entire internal range'],
));
echo "Added CIDR: 10.0.0.0/8\n";

$backend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '172.16.0.0/12',
    metadata: ['reason' => 'Block private range'],
));
echo "Added CIDR: 172.16.0.0/12\n";

// Add path-based blocks
$backend->append(new PatternEntry(
    kind: PatternKind::PATH_PREFIX,
    value: '/admin',
    metadata: ['reason' => 'Block admin path'],
));
echo "Added PATH_PREFIX: /admin\n";

$backend->append(new PatternEntry(
    kind: PatternKind::PATH_EXACT,
    value: '/secret',
    metadata: ['reason' => 'Block exact path'],
));
echo "Added PATH_EXACT: /secret\n";

$backend->append(new PatternEntry(
    kind: PatternKind::PATH_REGEX,
    value: '/^\/api\/v\d+\/internal/',
    metadata: ['reason' => 'Block internal API versions'],
));
echo "Added PATH_REGEX: /api/v*/internal\n";

// Add header-based blocks
$backend->append(new PatternEntry(
    kind: PatternKind::HEADER_REGEX,
    value: '/bot|crawler|spider/i',
    target: 'User-Agent',
    metadata: ['reason' => 'Block bots'],
));
echo "Added HEADER_REGEX: bots in User-Agent\n";

$backend->append(new PatternEntry(
    kind: PatternKind::HEADER_EXACT,
    value: 'BadBot/1.0',
    target: 'User-Agent',
    metadata: ['reason' => 'Block specific User-Agent'],
));
echo "Added HEADER_EXACT: BadBot/1.0\n\n";

// Show the blocklist file contents
echo "=== Blocklist File Contents ===\n";
echo file_get_contents($blocklistFile);
echo "\n";

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
$testRequest = function (
    string $desc,
    string $path,
    string $ip = '203.0.113.1',
    array $headers = []
) use ($middleware, $handler): void {
    $headers = array_merge(['User-Agent' => 'Mozilla/5.0'], $headers);
    $request = new ServerRequest('GET', $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $handler);

    $status = $response->getStatusCode();
    $result = $status === 200 ? 'ALLOW' : 'BLOCK';
    $rule = in_array($response->getHeaderLine('X-Phirewall-Matched'), ['', '0'], true) ? '-' : $response->getHeaderLine('X-Phirewall-Matched');

    echo sprintf("  [%s] %-50s\n", $result, $desc);
    if ($status !== 200) {
        echo sprintf("         Blocked by: %s\n", $rule);
    }
};

echo "=== Testing Blocklist ===\n\n";

echo "Test 1: IP Address Blocking\n";
$testRequest('Normal IP (203.0.113.1)', '/api/users', '203.0.113.1');
$testRequest('Blocked IP (192.168.1.100)', '/api/users', '192.168.1.100');
$testRequest('Blocked IP with expiry (192.168.1.101)', '/api/users', '192.168.1.101');
$testRequest('Blocked IPv6 (2001:db8::1)', '/api/users', '2001:db8::1');
echo "\n";

echo "Test 2: CIDR Range Blocking\n";
$testRequest('In 10.0.0.0/8 range (10.1.2.3)', '/api/users', '10.1.2.3');
$testRequest('In 172.16.0.0/12 range (172.20.1.1)', '/api/users', '172.20.1.1');
$testRequest('Outside blocked ranges (8.8.8.8)', '/api/users', '8.8.8.8');
echo "\n";

echo "Test 3: Path-Based Blocking\n";
$testRequest('Normal path (/api/users)', '/api/users', '8.8.8.8');
$testRequest('Blocked prefix (/admin)', '/admin', '8.8.8.8');
$testRequest('Blocked prefix (/admin/login)', '/admin/login', '8.8.8.8');
$testRequest('Blocked exact (/secret)', '/secret', '8.8.8.8');
$testRequest('Not blocked (/secrets)', '/secrets', '8.8.8.8');
$testRequest('Blocked regex (/api/v1/internal)', '/api/v1/internal', '8.8.8.8');
$testRequest('Blocked regex (/api/v2/internal/data)', '/api/v2/internal/data', '8.8.8.8');
$testRequest('Not blocked (/api/v1/public)', '/api/v1/public', '8.8.8.8');
echo "\n";

echo "Test 4: Header-Based Blocking\n";
$testRequest('Normal User-Agent', '/api/users', '8.8.8.8', ['User-Agent' => 'Mozilla/5.0']);
$testRequest('Bot User-Agent', '/api/users', '8.8.8.8', ['User-Agent' => 'Googlebot/2.1']);
$testRequest('Crawler User-Agent', '/api/users', '8.8.8.8', ['User-Agent' => 'WebCrawler/1.0']);
$testRequest('Spider User-Agent', '/api/users', '8.8.8.8', ['User-Agent' => 'Spider 1.0']);
$testRequest('Exact match BadBot', '/api/users', '8.8.8.8', ['User-Agent' => 'BadBot/1.0']);
echo "\n";

// =============================================================================
// PATTERN KIND REFERENCE
// =============================================================================

echo "=== Pattern Kind Reference ===\n\n";

echo "Available pattern kinds:\n";
echo "  PatternKind::IP           - Exact IP address match\n";
echo "  PatternKind::CIDR         - CIDR range match (e.g., 10.0.0.0/8)\n";
echo "  PatternKind::PATH_EXACT   - Exact path match\n";
echo "  PatternKind::PATH_PREFIX  - Path prefix match\n";
echo "  PatternKind::PATH_REGEX   - Path regex match\n";
echo "  PatternKind::HEADER_EXACT - Exact header value match\n";
echo "  PatternKind::HEADER_REGEX - Header value regex match\n";
echo "  PatternKind::REQUEST_REGEX - Full request regex match\n";
echo "\n";

echo "PatternEntry properties:\n";
echo "  kind      - Pattern type (required)\n";
echo "  value     - Pattern value (required)\n";
echo "  target    - Target field for header patterns (e.g., 'User-Agent')\n";
echo "  expiresAt - Unix timestamp for auto-expiry (optional)\n";
echo "  addedAt   - Unix timestamp when added (optional, auto-set)\n";
echo "  metadata  - Array of additional info (optional)\n";
echo "\n";

// =============================================================================
// CLEANUP
// =============================================================================

echo "=== Diagnostics ===\n";
$counters = $diagnostics->all();
echo "Blocked: " . ($counters['blocklisted']['total'] ?? 0) . "\n";
echo "Allowed: " . ($counters['passed']['total'] ?? 0) . "\n";

// Clean up temp file
unlink($blocklistFile);
echo "\nCleaned up temporary blocklist file.\n";

echo "\n=== Example Complete ===\n";
