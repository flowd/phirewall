<?php

/**
 * Example 19: Suspicious Headers Detection
 *
 * Demonstrates blocking requests that are missing standard HTTP headers
 * which real browsers always send (Accept, Accept-Language, Accept-Encoding).
 * Attack tools and scrapers often omit these.
 *
 * Run: php examples/19-header-analysis.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Suspicious Headers Detection Example ===\n\n";

$config = new Config(new InMemoryCache());

// Block requests missing standard browser headers
$config->blocklists->suspiciousHeaders();

$firewall = new Firewall($config);

echo "Rules configured:\n";
echo "  - Block requests missing: Accept, Accept-Language, Accept-Encoding\n\n";

// Simulate requests
echo "=== Request Simulation ===\n\n";

// 1. Normal browser request (all headers present)
$normalRequest = (new ServerRequest('GET', '/'))
    ->withHeader('Accept', 'text/html,application/xhtml+xml')
    ->withHeader('Accept-Language', 'en-US,en;q=0.9')
    ->withHeader('Accept-Encoding', 'gzip, deflate, br');

$result = $firewall->decide($normalRequest);
echo sprintf("  %-45s => %s\n", 'Normal browser (all headers)', $result->isPass() ? 'ALLOWED' : 'BLOCKED');

// 2. Scraper (missing Accept-Language)
$scraperRequest = (new ServerRequest('GET', '/'))
    ->withHeader('Accept', '*/*')
    ->withHeader('Accept-Encoding', 'gzip');

$result = $firewall->decide($scraperRequest);
echo sprintf("  %-45s => %s\n", 'Scraper (missing Accept-Language)', $result->isPass() ? 'ALLOWED' : 'BLOCKED');

// 3. Bot with no headers at all
$bareRequest = new ServerRequest('GET', '/');

$result = $firewall->decide($bareRequest);
echo sprintf("  %-45s => %s\n", 'Bot (no browser headers)', $result->isPass() ? 'ALLOWED' : 'BLOCKED');

// ── Custom required headers ──────────────────────────────────────────
echo "\n--- Custom Required Headers ---\n\n";

$config2 = new Config(new InMemoryCache());
$config2->blocklists->suspiciousHeaders('api-headers', ['Authorization', 'X-API-Key']);

$firewall2 = new Firewall($config2);

$apiRequest = (new ServerRequest('GET', '/api/data'))
    ->withHeader('Authorization', 'Bearer token123')
    ->withHeader('X-API-Key', 'key-abc');

$result = $firewall2->decide($apiRequest);
echo sprintf("  %-45s => %s\n", 'API request (all custom headers)', $result->isPass() ? 'ALLOWED' : 'BLOCKED');

$missingKeyRequest = (new ServerRequest('GET', '/api/data'))
    ->withHeader('Authorization', 'Bearer token123');

$result = $firewall2->decide($missingKeyRequest);
echo sprintf("  %-45s => %s\n", 'API request (missing X-API-Key)', $result->isPass() ? 'ALLOWED' : 'BLOCKED');

echo "\n=== Example Complete ===\n";
