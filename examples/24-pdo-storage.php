<?php

/**
 * Example 24: PdoCache Storage Backend
 *
 * Demonstrates using PdoCache with SQLite for persistent rate limiting
 * counters. PdoCache also supports MySQL and PostgreSQL for multi-server
 * deployments with a shared database.
 *
 * Run: php examples/24-pdo-storage.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\PdoCache;
use Nyholm\Psr7\ServerRequest;

echo "=== PdoCache Storage Backend Example ===\n\n";

// --- SQLite (in-memory for this demo, use a file path for persistence) ---

$pdo = new PDO('sqlite::memory:');
$cache = new PdoCache($pdo);
$config = new Config($cache);

echo "Backend: SQLite (in-memory)\n";
echo "Table auto-created on first use.\n\n";

// --- Configure rate limiting ---

$config->throttles->add('api', limit: 5, period: 60, key: KeyExtractors::ip());

$config->fail2ban->add('login', threshold: 3, period: 300, ban: 600,
    filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

$firewall = new Firewall($config);

// --- Simulate requests ---

echo "Sending 7 API requests from 10.0.0.1...\n";
for ($i = 1; $i <= 7; ++$i) {
    $request = new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
    $result = $firewall->decide($request);
    echo sprintf("  Request #%d: %s\n", $i, $result->isPass() ? 'PASS' : 'THROTTLED');
}

echo "\nSending 4 failed login attempts from 10.0.0.2...\n";
for ($i = 1; $i <= 4; ++$i) {
    $request = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
        ->withHeader('X-Login-Failed', '1');
    $result = $firewall->decide($request);
    echo sprintf("  Attempt #%d: %s\n", $i, $result->isPass() ? 'PASS' : 'BANNED');
}

// --- Reset helpers ---

echo "\nResetting throttle for 10.0.0.1...\n";
$firewall->resetThrottle('api', '10.0.0.1');

$request = new ServerRequest('GET', '/api/data', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
$result = $firewall->decide($request);
echo sprintf("  After reset: %s\n", $result->isPass() ? 'PASS' : 'THROTTLED');

echo "\nChecking ban status for 10.0.0.2...\n";
echo sprintf("  isBanned: %s\n", $firewall->isBanned('login', '10.0.0.2') ? 'YES' : 'no');

// --- Connection examples (not executed, for reference) ---

echo "\n--- Connection Examples (reference only) ---\n";
echo <<<'EXAMPLES'

// SQLite with file persistence and WAL mode:
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$pdo->exec('PRAGMA journal_mode=WAL');
$cache = new PdoCache($pdo);

// MySQL (shared across multiple app servers):
$pdo = new PDO('mysql:host=db.example.com;dbname=myapp', 'user', 'password');
$cache = new PdoCache($pdo);

// PostgreSQL (shared across multiple app servers):
$pdo = new PDO('pgsql:host=db.example.com;dbname=myapp', 'user', 'password');
$cache = new PdoCache($pdo);

// Custom table name:
$cache = new PdoCache($pdo, 'my_firewall_cache');

EXAMPLES;

echo "\n=== Example Complete ===\n";
