<?php

/**
 * Example 05: Cross-Site Scripting (XSS) Prevention
 *
 * This example demonstrates how to block XSS attacks using:
 * - OWASP CRS-style rules
 * - Pattern detection in query parameters and headers
 *
 * Common XSS patterns detected:
 * - Script tags
 * - Event handlers (onload, onerror, etc.)
 * - JavaScript protocol
 * - Data URIs
 * - SVG-based XSS
 * - HTML entity encoding attacks
 *
 * Run: php examples/05-xss-prevention.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== XSS Prevention Example ===\n\n";

// =============================================================================
// OWASP CRS RULES FOR XSS
// =============================================================================

$xssRules = <<<'CRS'
# =============================================================================
# Cross-Site Scripting (XSS) Detection Rules
# Based on OWASP Core Rule Set patterns
# =============================================================================

# XSS - Script tags
# Example: <script>alert('xss')</script>
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS: Script tag detected'"

# XSS - Closing script tag
# Example: </script>
SecRule ARGS "@rx (?i)</script>" \
    "id:941101,phase:2,deny,msg:'XSS: Closing script tag'"

# XSS - Event handlers (onload, onerror, onclick, etc.)
# Example: <img src=x onerror=alert(1)>
SecRule ARGS "@rx (?i)\bon(load|error|click|mouseover|focus|blur|change|submit|keyup|keydown|keypress|mouse\w+|drag\w+)\s*=" \
    "id:941110,phase:2,deny,msg:'XSS: Event handler detected'"

# XSS - JavaScript protocol
# Example: <a href="javascript:alert(1)">
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS: JavaScript protocol'"

# XSS - VBScript protocol (IE)
# Example: <a href="vbscript:msgbox(1)">
SecRule ARGS "@rx (?i)vbscript\s*:" \
    "id:941121,phase:2,deny,msg:'XSS: VBScript protocol'"

# XSS - Data URI with base64
# Example: <img src="data:image/svg+xml;base64,PHN2Zy...">
SecRule ARGS "@rx (?i)data\s*:[^,]*;base64" \
    "id:941130,phase:2,deny,msg:'XSS: Data URI with base64'"

# XSS - SVG onload
# Example: <svg onload=alert(1)>
SecRule ARGS "@rx (?i)<svg[^>]*\bon\w+\s*=" \
    "id:941140,phase:2,deny,msg:'XSS: SVG event handler'"

# XSS - iframe injection
# Example: <iframe src="http://evil.com">
SecRule ARGS "@rx (?i)<iframe[^>]*>" \
    "id:941150,phase:2,deny,msg:'XSS: iframe injection'"

# XSS - Object/embed tags
# Example: <object data="evil.swf">
SecRule ARGS "@rx (?i)<(object|embed|applet)[^>]*>" \
    "id:941160,phase:2,deny,msg:'XSS: Object/embed tag'"

# XSS - Style tag with expression
# Example: <style>body{background:expression(alert(1))}</style>
SecRule ARGS "@rx (?i)<style[^>]*>" \
    "id:941170,phase:2,deny,msg:'XSS: Style tag'"

# XSS - Expression function (IE)
# Example: style="width:expression(alert(1))"
SecRule ARGS "@rx (?i)expression\s*\(" \
    "id:941180,phase:2,deny,msg:'XSS: CSS expression'"

# XSS - HTML5 event handlers
# Example: <body onpageshow=alert(1)>
SecRule ARGS "@rx (?i)\bon(pageshow|pagehide|popstate|hashchange|storage|message|online|offline)\s*=" \
    "id:941190,phase:2,deny,msg:'XSS: HTML5 event handler'"

# XSS - Meta refresh/redirect
# Example: <meta http-equiv="refresh" content="0;url=javascript:alert(1)">
SecRule ARGS "@rx (?i)<meta[^>]*http-equiv\s*=\s*['\"]?refresh" \
    "id:941200,phase:2,deny,msg:'XSS: Meta refresh'"

# XSS - Link tag stylesheet with expression
# Example: <link rel="stylesheet" href="javascript:alert(1)">
SecRule ARGS "@rx (?i)<link[^>]*href\s*=\s*['\"]?javascript" \
    "id:941210,phase:2,deny,msg:'XSS: Link with JavaScript href'"

# XSS - Base tag hijacking
# Example: <base href="http://evil.com/">
SecRule ARGS "@rx (?i)<base[^>]*>" \
    "id:941220,phase:2,deny,msg:'XSS: Base tag injection'"

# XSS - Form action hijacking
# Example: <form action="http://evil.com/steal">
SecRule ARGS "@rx (?i)<form[^>]*action\s*=" \
    "id:941230,phase:2,deny,msg:'XSS: Form action injection'"
CRS;

echo "Loading OWASP-style XSS detection rules...\n";
$result = SecRuleLoader::fromStringWithReport($xssRules);
$coreRuleSet = $result['rules'];

echo "Rules loaded: {$result['parsed']}\n";
echo "Rules skipped: {$result['skipped']}\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$config = new Config(new InMemoryCache());
$config->owaspBlocklist('xss-prevention', $coreRuleSet);
$config->enableOwaspDiagnosticsHeader();

$firewall = new Firewall($config);

// =============================================================================
// TEST CASES
// =============================================================================

echo "=== Testing XSS Patterns ===\n\n";

$testCases = [
    // Safe requests
    [
        'description' => 'Safe: Normal text input',
        'url' => '/api/comment?text=Hello+World',
        'expected' => 'ALLOW',
    ],
    [
        'description' => 'Safe: Numeric input',
        'url' => '/api/users?page=1&limit=10',
        'expected' => 'ALLOW',
    ],
    [
        'description' => 'Safe: HTML entities (encoded)',
        'url' => '/api/comment?text=%26lt%3Bscript%26gt%3B',
        'expected' => 'ALLOW',
    ],

    // Script tag attacks
    [
        'description' => 'XSS: Basic script tag',
        'url' => '/api/comment?text=<script>alert(1)</script>',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: Script with src',
        'url' => '/api/comment?text=<script+src=http://evil.com/xss.js>',
        'expected' => 'BLOCK',
    ],

    // Event handler attacks
    [
        'description' => 'XSS: img onerror',
        'url' => '/api/comment?text=<img+src=x+onerror=alert(1)>',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: body onload',
        'url' => '/api/comment?text=<body+onload=alert(1)>',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: div onclick',
        'url' => '/api/comment?text=<div+onclick=alert(1)>Click</div>',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: input onfocus',
        'url' => '/api/comment?text=<input+onfocus=alert(1)+autofocus>',
        'expected' => 'BLOCK',
    ],

    // JavaScript protocol
    [
        'description' => 'XSS: JavaScript href',
        'url' => '/api/comment?text=<a+href="javascript:alert(1)">click</a>',
        'expected' => 'BLOCK',
    ],
    // Note: Obfuscation with spaces inside "javascript" is not caught by basic rules
    // A more comprehensive rule would be: (?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:
    [
        'description' => 'XSS: JavaScript with spaces (obfuscation)',
        'url' => '/api/comment?text=<a+href="java+script:alert(1)">',
        'expected' => 'ALLOW',
    ],

    // Data URI attacks
    [
        'description' => 'XSS: Data URI base64',
        'url' => '/api/comment?text=<img+src="data:image/svg+xml;base64,PHN2Zz4=">',
        'expected' => 'BLOCK',
    ],

    // SVG attacks
    [
        'description' => 'XSS: SVG onload',
        'url' => '/api/comment?text=<svg+onload=alert(1)>',
        'expected' => 'BLOCK',
    ],

    // iframe attacks
    [
        'description' => 'XSS: iframe injection',
        'url' => '/api/comment?text=<iframe+src="http://evil.com">',
        'expected' => 'BLOCK',
    ],

    // Object/embed attacks
    [
        'description' => 'XSS: object tag',
        'url' => '/api/comment?text=<object+data="evil.swf">',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: embed tag',
        'url' => '/api/comment?text=<embed+src="evil.swf">',
        'expected' => 'BLOCK',
    ],

    // Style attacks
    [
        'description' => 'XSS: style tag',
        'url' => '/api/comment?text=<style>body{background:url(evil)}</style>',
        'expected' => 'BLOCK',
    ],
    [
        'description' => 'XSS: CSS expression',
        'url' => '/api/comment?text=<div+style="width:expression(alert(1))">',
        'expected' => 'BLOCK',
    ],

    // Meta tag attacks
    [
        'description' => 'XSS: meta refresh',
        'url' => '/api/comment?text=<meta+http-equiv="refresh"+content="0;url=javascript:alert(1)">',
        'expected' => 'BLOCK',
    ],

    // Form hijacking
    [
        'description' => 'XSS: form action',
        'url' => '/api/comment?text=<form+action="http://evil.com">',
        'expected' => 'BLOCK',
    ],

    // Base tag hijacking
    [
        'description' => 'XSS: base tag',
        'url' => '/api/comment?text=<base+href="http://evil.com/">',
        'expected' => 'BLOCK',
    ],
];

$passed = 0;
$failed = 0;

foreach ($testCases as $test) {
    $request = new ServerRequest('GET', $test['url']);
    $result = $firewall->decide($request);

    $actual = $result->isBlocked() ? 'BLOCK' : 'ALLOW';
    $status = $actual === $test['expected'] ? 'PASS' : 'FAIL';

    if ($status === 'PASS') {
        $passed++;
    } else {
        $failed++;
    }

    echo sprintf("[%s] %s\n", $status, $test['description']);

    if ($result->isBlocked()) {
        $ruleId = $result->headers['X-Phirewall-Owasp-Rule'] ?? 'n/a';
        echo sprintf("       Blocked by rule: %s\n", $ruleId);
    }

    if ($status === 'FAIL') {
        echo sprintf("       Expected: %s, Got: %s\n", $test['expected'], $actual);
    }
}

echo "\n=== Results ===\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";

echo "\n=== Protection Summary ===\n";
$counters = $config->getDiagnosticsCounters();
echo "XSS attacks blocked: " . ($counters['blocklisted']['total'] ?? 0) . "\n";
echo "Safe requests allowed: " . ($counters['passed']['total'] ?? 0) . "\n";

echo "\n=== Example Complete ===\n";
