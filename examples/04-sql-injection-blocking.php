<?php

/**
 * Example 04: SQL Injection Blocking
 *
 * This example demonstrates how to block SQL injection attacks using:
 * - OWASP CRS-style rules
 * - Custom pattern matching
 *
 * Common SQLi patterns detected:
 * - UNION SELECT attacks
 * - Boolean-based injection
 * - Time-based injection
 * - Comment injection
 * - Hex encoding
 *
 * Run: php examples/04-sql-injection-blocking.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== SQL Injection Blocking Example ===\n\n";

// =============================================================================
// OWASP CRS RULES FOR SQL INJECTION
// =============================================================================

$sqlInjectionRules = <<<'CRS'
# =============================================================================
# SQL Injection Detection Rules
# Based on OWASP Core Rule Set patterns
# =============================================================================

# SQL Injection - UNION SELECT attacks
# Example: ?id=1 UNION SELECT username,password FROM users
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" \
    "id:942100,phase:2,deny,msg:'SQL Injection: UNION SELECT'"

# SQL Injection - SELECT FROM attacks
# Example: ?name='; SELECT * FROM users--
SecRule ARGS "@rx (?i)\bselect\b.*\bfrom\b" \
    "id:942110,phase:2,deny,msg:'SQL Injection: SELECT FROM'"

# SQL Injection - Boolean-based blind
# Example: ?id=1' OR '1'='1
SecRule ARGS "@rx (?i)('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Injection: Boolean-based'"

# SQL Injection - Numeric boolean
# Example: ?id=1 OR 1=1
SecRule ARGS "@rx (?i)\bor\s+\d+\s*=\s*\d+" \
    "id:942130,phase:2,deny,msg:'SQL Injection: Numeric boolean'"

# SQL Injection - Comment sequences
# Example: ?id=1--
# Example: ?id=1/**/
SecRule ARGS "@rx (--\s*$|/\*|\*/)" \
    "id:942140,phase:2,deny,msg:'SQL Injection: Comment sequence'"

# SQL Injection - Stacked queries
# Example: ?id=1; DROP TABLE users
SecRule ARGS "@rx (?i);\s*(drop|delete|insert|update|create|alter|truncate)\b" \
    "id:942150,phase:2,deny,msg:'SQL Injection: Stacked query'"

# SQL Injection - Hex encoding
# Example: ?id=0x61646D696E (hex for 'admin')
SecRule ARGS "@rx (?i)0x[0-9a-f]{4,}" \
    "id:942160,phase:2,deny,msg:'SQL Injection: Hex encoding'"

# SQL Injection - Benchmark/Sleep (time-based)
# Example: ?id=1 AND SLEEP(5)
SecRule ARGS "@rx (?i)\b(benchmark|sleep|waitfor)\s*\(" \
    "id:942170,phase:2,deny,msg:'SQL Injection: Time-based'"

# SQL Injection - Common SQL functions
# Example: ?id=CHAR(65)
SecRule ARGS "@rx (?i)\b(char|concat|substring|ascii|ord)\s*\(" \
    "id:942180,phase:2,deny,msg:'SQL Injection: SQL function'"

# SQL Injection - Database enumeration
# Example: ?id=1 AND (SELECT count(*) FROM information_schema.tables)>0
SecRule ARGS "@rx (?i)information_schema" \
    "id:942190,phase:2,deny,msg:'SQL Injection: DB enumeration'"
CRS;

echo "Loading OWASP-style SQL injection rules...\n";
$result = SecRuleLoader::fromStringWithReport($sqlInjectionRules);
$coreRuleSet = $result['rules'];

echo sprintf('Rules loaded: %d%s', $result['parsed'], PHP_EOL);
echo "Rules skipped: {$result['skipped']}\n\n";

// List loaded rules
echo "Active rules:\n";
foreach ($coreRuleSet->ids() as $id) {
    echo sprintf('  - Rule %d: ', $id) . ($coreRuleSet->isEnabled($id) ? 'enabled' : 'disabled') . "\n";
}

echo "\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$diagnostics = new DiagnosticsCounters();
$config = new Config(new InMemoryCache(), $diagnostics);
$config->enableResponseHeaders();
$config->blocklists->owasp('sql-injection', $coreRuleSet);

// Enable diagnostics header to see which rule matched
$config->enableOwaspDiagnosticsHeader();

$firewall = new Firewall($config);

// =============================================================================
// TEST CASES
// =============================================================================

echo "=== Testing SQL Injection Patterns ===\n\n";

$testCases = [
    // Safe requests
    [
        'description' => 'Safe: Normal search query',
        'url' => '/api/search?q=hello+world',
        'expected' => 'ALLOW',
    ],
    [
        'description' => 'Safe: Numeric ID',
        'url' => '/api/users?id=123',
        'expected' => 'ALLOW',
    ],
    [
        'description' => 'Safe: Normal filter',
        'url' => '/api/products?category=electronics&sort=price',
        'expected' => 'ALLOW',
    ],

    // SQL Injection attempts
    [
        'description' => 'SQLi: UNION SELECT attack',
        'url' => '/api/users?id=1+UNION+SELECT+username,password+FROM+users',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Boolean-based OR injection',
        'url' => "/api/login?user=admin'OR'1'='1",
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Numeric boolean',
        'url' => '/api/users?id=1+OR+1=1',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Comment-based',
        'url' => '/api/users?id=1--',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Block comment',
        'url' => '/api/users?id=1/**/UNION/**/SELECT',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Stacked DROP TABLE',
        'url' => '/api/users?id=1;DROP+TABLE+users',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Stacked DELETE',
        'url' => '/api/users?id=1;DELETE+FROM+users',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Hex encoding',
        'url' => '/api/users?name=0x61646D696E',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Time-based SLEEP',
        'url' => '/api/users?id=1+AND+SLEEP(5)',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Time-based BENCHMARK',
        'url' => '/api/users?id=1+AND+BENCHMARK(10000000,SHA1(1))',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: CHAR function',
        'url' => '/api/users?name=CHAR(65,66,67)',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: CONCAT function',
        'url' => '/api/users?name=CONCAT(0x3a,user())',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: Information schema',
        'url' => '/api/users?id=1+AND+(SELECT+*+FROM+information_schema.tables)',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'SQLi: SELECT FROM users',
        'url' => "/api/search?q=';SELECT+*+FROM+users--",
        'expected' => 'BLOCK',
    ],
];

$passed = 0;
$failed = 0;

foreach ($testCases as $testCase) {
    $request = new ServerRequest('GET', $testCase['url']);
    $result = $firewall->decide($request);

    $actual = $result->isBlocked() ? 'BLOCK' : 'ALLOW';
    $status = $actual === $testCase['expected'] ? 'PASS' : 'FAIL';

    if ($status === 'PASS') {
        ++$passed;
    } else {
        ++$failed;
    }

    echo sprintf(
        "[%s] %s\n",
        $status,
        $testCase['description']
    );

    if ($result->isBlocked()) {
        $ruleId = $result->headers['X-Phirewall-Owasp-Rule'] ?? 'n/a';
        echo sprintf("       Blocked by rule: %s\n", $ruleId);
    }

    // Show URL for failed tests
    if ($status === 'FAIL') {
        echo sprintf("       URL: %s\n", $testCase['url']);
        echo sprintf("       Expected: %s, Got: %s\n", $testCase['expected'], $actual);
    }
}

echo "\n=== Results ===\n";
echo sprintf('Passed: %d%s', $passed, PHP_EOL);
echo sprintf('Failed: %d%s', $failed, PHP_EOL);

echo "\n=== Diagnostics ===\n";
$counters = $diagnostics->all();
echo "Blocked requests: " . ($counters['blocklisted']['total'] ?? 0) . "\n";
echo "Passed requests: " . ($counters['passed']['total'] ?? 0) . "\n";

echo "\n=== Example Complete ===\n";
