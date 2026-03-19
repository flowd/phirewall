<?php

/**
 * Example 18: Trusted Bot Verification
 *
 * Demonstrates how to safelist verified search engine bots using
 * reverse DNS verification. Only bots whose IPs resolve to known
 * hostnames (e.g. *.googlebot.com) are safelisted.
 *
 * Run: php examples/18-trusted-bots.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Trusted Bot Verification Example ===\n\n";

$cache = new InMemoryCache();
$config = new Config($cache);

// Safelist known bots (Googlebot, Bingbot, etc.) via RDNS verification.
// Pass a PSR-16 cache to avoid repeated DNS lookups (cached for 24 hours by default).
$config->safelists->trustedBots(cache: $cache);

// Also safelist a custom internal bot
$config->safelists->trustedBots('custom-bots', [
    ['ua' => 'mycompany-crawler', 'hostname' => '.crawler.mycompany.com'],
], cache: $cache);

// Block everything else for this demo
$config->blocklists->add('block-all', fn($r): bool => true);

$firewall = new Firewall($config);

echo "Rules configured:\n";
echo "  - Trusted bots safelist (built-in: Google, Bing, Baidu, etc.)\n";
echo "  - Custom bot safelist (mycompany-crawler)\n";
echo "  - Block-all fallback\n\n";

// Simulate requests
$requests = [
    [
        'desc' => 'Real Googlebot (RDNS would verify in production)',
        'ua' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'ip' => '66.249.66.1',
    ],
    [
        'desc' => 'Regular browser (not a bot)',
        'ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'ip' => '203.0.113.50',
    ],
    [
        'desc' => 'Fake Googlebot (RDNS would fail in production)',
        'ua' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
        'ip' => '1.2.3.4',
    ],
];

echo "=== Simulation ===\n";
echo "(Note: RDNS verification requires real DNS; results may differ in production)\n\n";

foreach ($requests as $r) {
    $request = new ServerRequest('GET', '/', [
        'User-Agent' => $r['ua'],
    ], null, '1.1', ['REMOTE_ADDR' => $r['ip']]);

    $result = $firewall->decide($request);
    $status = $result->isPass() ? 'ALLOWED' : 'BLOCKED';
    echo sprintf("  %-50s => %s (%s)\n", $r['desc'], $status, $result->outcome->value);
}

echo "\n=== Example Complete ===\n";
