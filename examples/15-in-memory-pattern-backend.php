<?php

/**
 * Example 15: In-Memory Pattern Backend
 *
 * This example demonstrates how to use the InMemoryPatternBackend for
 * configuration-based blocklists without file I/O.
 *
 * Use cases:
 * - Hardcoded CIDR ranges (e.g., block internal networks from public API)
 * - Configuration-driven blocklists
 * - Testing and development
 *
 * Run: php examples/15-in-memory-pattern-backend.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== In-Memory Pattern Backend Example ===\n\n";

// =============================================================================
// SETUP
// =============================================================================

$config = new Config(new InMemoryCache());

// =============================================================================
// EXAMPLE 1: CIDR-BASED IP BLOCKING
// =============================================================================

echo "--- Example 1: CIDR-Based IP Blocking (Simple One-Step) ---\n\n";

// Simple approach: Create backend and register as blocklist in one step
// Use patternBlocklist() for the most common case
$ipBackend = $config->patternBlocklist('private-networks', [
    new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
    new PatternEntry(PatternKind::CIDR, '172.16.0.0/12'),
    new PatternEntry(PatternKind::CIDR, '192.168.0.0/16'),
    new PatternEntry(PatternKind::IP, '127.0.0.1'),
]);

echo "Blocked ranges:\n";
echo "  - 10.0.0.0/8 (Class A private)\n";
echo "  - 172.16.0.0/12 (Class B private)\n";
echo "  - 192.168.0.0/16 (Class C private)\n";
echo "  - 127.0.0.1 (localhost)\n\n";

// =============================================================================
// EXAMPLE 2: PATH-BASED BLOCKING
// =============================================================================

echo "--- Example 2: Path-Based Blocking (Two-Step for Reusability) ---\n\n";

// Two-step approach: Useful when sharing a backend between multiple rules
// or when you need more control over backend configuration
$pathBackend = $config->inMemoryPatternBackend('blocked-paths', [
    // Exact path matches
    new PatternEntry(PatternKind::PATH_EXACT, '/admin'),
    new PatternEntry(PatternKind::PATH_EXACT, '/.env'),

    // Prefix matches
    new PatternEntry(PatternKind::PATH_PREFIX, '/wp-'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/phpmyadmin'),

    // Regex matches
    new PatternEntry(PatternKind::PATH_REGEX, '/\.(git|svn|hg)/'),
]);

$config->blocklistFromBackend('block-sensitive-paths', 'blocked-paths');

echo "Blocked paths:\n";
echo "  - /admin (exact)\n";
echo "  - /.env (exact)\n";
echo "  - /wp-* (prefix)\n";
echo "  - /phpmyadmin* (prefix)\n";
echo "  - /.git/, /.svn/, /.hg/ (regex)\n\n";

// =============================================================================
// EXAMPLE 3: HEADER-BASED BLOCKING
// =============================================================================

echo "--- Example 3: Header-Based Blocking ---\n\n";

$headerBackend = $config->inMemoryPatternBackend('blocked-headers', [
    // Block specific User-Agents
    new PatternEntry(
        kind: PatternKind::HEADER_REGEX,
        value: '/sqlmap|nikto|nmap|masscan/i',
        target: 'User-Agent'
    ),

    // Block empty User-Agent
    new PatternEntry(
        kind: PatternKind::HEADER_EXACT,
        value: '',
        target: 'User-Agent'
    ),

    // Block specific referers
    new PatternEntry(
        kind: PatternKind::HEADER_REGEX,
        value: '/spam-site\.com|malware\.net/i',
        target: 'Referer'
    ),
]);

$config->blocklistFromBackend('block-bad-headers', 'blocked-headers');

echo "Blocked headers:\n";
echo "  - User-Agent matching: sqlmap, nikto, nmap, masscan\n";
echo "  - Empty User-Agent\n";
echo "  - Referer from spam-site.com or malware.net\n\n";

// =============================================================================
// EXAMPLE 4: DYNAMIC ENTRIES WITH EXPIRATION
// =============================================================================

echo "--- Example 4: Dynamic Entries with Expiration ---\n\n";

$dynamicBackend = $config->inMemoryPatternBackend('dynamic-blocks');

// Add entries that expire
$dynamicBackend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.100',
    expiresAt: time() + 3600,  // Expires in 1 hour
    metadata: ['reason' => 'Suspicious activity'],
));

$dynamicBackend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '198.51.100.0/24',
    expiresAt: time() + 86400,  // Expires in 24 hours
    metadata: ['reason' => 'DDoS source'],
));

// Permanent block (no expiration)
$dynamicBackend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.200',
    metadata: ['reason' => 'Known bad actor'],
));

$config->blocklistFromBackend('dynamic-blocklist', 'dynamic-blocks');

echo "Dynamic entries added:\n";
echo "  - 203.0.113.100 (expires in 1 hour)\n";
echo "  - 198.51.100.0/24 (expires in 24 hours)\n";
echo "  - 203.0.113.200 (permanent)\n\n";

// =============================================================================
// TESTING
// =============================================================================

echo "=== Testing Blocklists ===\n\n";

$firewall = new Firewall($config);

$testCases = [
    // IP tests
    ['IP: Private (10.x)', 'GET', '/', [], '10.0.0.1', 'BLOCK'],
    ['IP: Private (172.x)', 'GET', '/', [], '172.16.0.1', 'BLOCK'],
    ['IP: Private (192.x)', 'GET', '/', [], '192.168.1.1', 'BLOCK'],
    ['IP: Localhost', 'GET', '/', [], '127.0.0.1', 'BLOCK'],
    ['IP: Public (allowed)', 'GET', '/', [], '8.8.8.8', 'ALLOW'],

    // Path tests
    ['Path: /admin', 'GET', '/admin', [], '8.8.8.8', 'BLOCK'],
    ['Path: /.env', 'GET', '/.env', [], '8.8.8.8', 'BLOCK'],
    ['Path: /wp-admin', 'GET', '/wp-admin/index.php', [], '8.8.8.8', 'BLOCK'],
    ['Path: /.git/config', 'GET', '/.git/config', [], '8.8.8.8', 'BLOCK'],
    ['Path: /api/users', 'GET', '/api/users', [], '8.8.8.8', 'ALLOW'],

    // Header tests
    ['Header: sqlmap UA', 'GET', '/', ['User-Agent' => 'sqlmap/1.0'], '8.8.8.8', 'BLOCK'],
    ['Header: Empty UA', 'GET', '/', ['User-Agent' => ''], '8.8.8.8', 'BLOCK'],
    ['Header: Normal UA', 'GET', '/', ['User-Agent' => 'Mozilla/5.0'], '8.8.8.8', 'ALLOW'],
    ['Header: Bad Referer', 'GET', '/', ['Referer' => 'https://spam-site.com/'], '8.8.8.8', 'BLOCK'],

    // Dynamic blocks
    ['Dynamic: Temp IP', 'GET', '/', [], '203.0.113.100', 'BLOCK'],
    ['Dynamic: Temp CIDR', 'GET', '/', [], '198.51.100.50', 'BLOCK'],
    ['Dynamic: Perm IP', 'GET', '/', [], '203.0.113.200', 'BLOCK'],
];

$passed = 0;
$failed = 0;

foreach ($testCases as [$desc, $method, $path, $headers, $ip, $expected]) {
    $request = new ServerRequest($method, $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $result = $firewall->decide($request);

    $actual = $result->isBlocked() ? 'BLOCK' : 'ALLOW';
    $status = $actual === $expected ? 'PASS' : 'FAIL';

    if ($status === 'PASS') {
        ++$passed;
    } else {
        ++$failed;
    }

    echo sprintf("[%s] %-25s => %s\n", $status, $desc, $actual);
}

echo "\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";

// =============================================================================
// BACKEND STATS
// =============================================================================

echo "\n=== Backend Statistics ===\n\n";

echo "private-networks: " . $ipBackend->count() . " entries\n";
echo "blocked-paths: " . $pathBackend->count() . " entries\n";
echo "blocked-headers: " . $headerBackend->count() . " entries\n";
echo "dynamic-blocks: " . $dynamicBackend->count() . " entries\n";

// =============================================================================
// USAGE PATTERNS
// =============================================================================

echo "\n=== Common Usage Patterns ===\n\n";

echo "1. Block cloud provider ranges from sensitive endpoints:\n";
echo <<<'CODE'
   $backend = $config->inMemoryPatternBackend('cloud-ips', [
       new PatternEntry(PatternKind::CIDR, '13.32.0.0/15'),   // AWS CloudFront
       new PatternEntry(PatternKind::CIDR, '34.0.0.0/9'),     // Google Cloud
       new PatternEntry(PatternKind::CIDR, '40.74.0.0/15'),   // Azure
   ]);
CODE;
echo "\n\n";

echo "2. Allow only specific countries (by known IP ranges):\n";
echo <<<'CODE'
   $allowedBackend = $config->inMemoryPatternBackend('allowed-ips', [
       new PatternEntry(PatternKind::CIDR, '...'),  // Your country's ranges
   ]);
   // Use as safelist instead of blocklist
CODE;
echo "\n\n";

echo "3. Block Tor exit nodes (loaded from external source):\n";
echo <<<'CODE'
   $torExits = file('https://check.torproject.org/exit-addresses');
   $entries = array_map(
       fn($ip) => new PatternEntry(PatternKind::IP, trim($ip)),
       $torExits
   );
   $backend = $config->inMemoryPatternBackend('tor-exits', $entries);
CODE;
echo "\n\n";

echo "=== Example Complete ===\n";
