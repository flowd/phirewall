<?php

/**
 * Example 14: OWASP Core Rule Set from Files
 *
 * This example demonstrates how to load OWASP Core Rule Set (CRS) style rules
 * from external configuration files, similar to how ModSecurity loads rules.
 *
 * Features shown:
 * - Loading rules from a directory
 * - Using @pmFromFile for phrase matching
 * - Enabling/disabling specific rules
 * - Integration with the Firewall
 *
 * Run: php examples/14-owasp-crs-files.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS from Files Example ===\n\n";

// =============================================================================
// LOAD RULES FROM DIRECTORY
// =============================================================================

$rulesDir = __DIR__ . '/14-owasp_crs_basic';

if (!is_dir($rulesDir)) {
    echo "Rules directory not found: $rulesDir\n";
    echo "This example requires the owasp_crs_basic/ folder with rule files.\n";
    exit(1);
}

echo "Loading rules from: $rulesDir\n\n";

// Load all rules from the directory
// This will parse .conf files and load .data files for @pmFromFile
$coreRuleSet = SecRuleLoader::fromDirectory($rulesDir);

// =============================================================================
// INSPECT LOADED RULES
// =============================================================================

echo "=== Loaded Rules ===\n\n";

$ruleIds = $coreRuleSet->ids();
echo sprintf("Total rules loaded: %d\n\n", count($ruleIds));

echo "Rule Status:\n";
foreach ($ruleIds as $id) {
    $enabled = $coreRuleSet->isEnabled($id) ? 'enabled' : 'disabled';
    echo sprintf("  Rule %d: %s\n", $id, $enabled);
}
echo "\n";

// =============================================================================
// RULE MANAGEMENT
// =============================================================================

echo "=== Rule Management ===\n\n";

// You can disable specific rules if they cause false positives
// $coreRuleSet->disable(933150);
// echo "Disabled rule 933150\n";

// Or enable a previously disabled rule
// $coreRuleSet->enable(933150);
// echo "Enabled rule 933150\n";

echo "All rules remain enabled for this demo\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$config = new Config(new InMemoryCache());
$config->owaspBlocklist('owasp', $coreRuleSet);

// Enable diagnostics header to see which rule matched
$config->enableOwaspDiagnosticsHeader();

$firewall = new Firewall($config);

echo "Firewall configured with OWASP rules\n\n";

// =============================================================================
// TEST CASES
// =============================================================================

echo "=== Testing OWASP Rules ===\n\n";

$testCases = [
    // Safe requests
    ['Safe: Normal request', '/api/users', 'ALLOW'],
    ['Safe: Normal query', '/search?q=hello', 'ALLOW'],

    // PHP function injection (should match rules in the .conf file)
    ['PHP: base64_decode', '/foo?cmd=base64_decode', 'BLOCK'],
    ['PHP: system call', '/any?foo=(system)(ls);', 'BLOCK'],
    // Note: CRS intentionally excludes 'eval' to avoid false positives (e.g., 'medieval')
    ['PHP: eval function (not in CRS)', '/page?x=eval(', 'ALLOW'],

    // These might match depending on the loaded rules
    ['PHP: shell_exec', '/api?cmd=shell_exec(', 'BLOCK'],
];

$passed = 0;
$failed = 0;

foreach ($testCases as [$desc, $url, $expected]) {
    $request = new ServerRequest('GET', $url);
    $result = $firewall->decide($request);

    $actual = $result->isBlocked() ? 'BLOCK' : 'ALLOW';
    $status = $actual === $expected ? 'PASS' : 'FAIL';

    if ($status === 'PASS') {
        $passed++;
    } else {
        $failed++;
    }

    echo sprintf("[%s] %s\n", $status, $desc);

    if ($result->isBlocked()) {
        $ruleId = $result->headers['X-Phirewall-Owasp-Rule'] ?? 'n/a';
        echo sprintf("       Blocked by rule: %s\n", $ruleId);
    }

    if ($status === 'FAIL') {
        echo sprintf("       Expected: %s, Got: %s\n", $expected, $actual);
    }
}

echo "\n=== Results ===\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";

// =============================================================================
// DIAGNOSTICS
// =============================================================================

echo "\n=== Diagnostics ===\n";
$counters = $config->getDiagnosticsCounters();
echo "Blocked: " . ($counters['blocklisted']['total'] ?? 0) . "\n";
echo "Passed: " . ($counters['passed']['total'] ?? 0) . "\n";

// =============================================================================
// FILE FORMAT REFERENCE
// =============================================================================

echo "\n=== File Format Reference ===\n\n";

echo "Rule files (.conf):\n";
echo <<<'CONF'
# Comment
SecRule ARGS "@rx pattern" \
    "id:123456,phase:2,deny,msg:'Description'"

# With phrase file
SecRule ARGS "@pmFromFile php-functions.data" \
    "id:123457,phase:2,deny,msg:'PHP function detected'"
CONF;
echo "\n\n";

echo "Phrase files (.data):\n";
echo <<<'DATA'
# One phrase per line
eval
exec
system
shell_exec
passthru
DATA;
echo "\n\n";

echo "Supported operators:\n";
echo "  @rx     - Regular expression match\n";
echo "  @pm     - Phrase match (inline)\n";
echo "  @pmFromFile - Phrase match from external file\n";
echo "  @eq     - Exact match\n";
echo "  @contains - Substring match\n";

echo "\n=== Example Complete ===\n";
