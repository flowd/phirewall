<?php

declare(strict_types=1);

/**
 * Example: Block known attack tools and vulnerability scanners.
 *
 * KnownScannerMatcher blocks requests whose User-Agent matches common attack tools:
 * sqlmap, nikto, nmap, masscan, nuclei, gobuster, wfuzz, metasploit, and more.
 *
 * The default list covers ~25 well-known tools. You can replace or extend it.
 */

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

$cache = new InMemoryCache();
$config = new Config($cache);

// Block all known scanners with default patterns
$config->blocklists->knownScanners();

// Extend defaults with custom patterns:
// $config->blocklists->knownScanners('scanners', [...KnownScannerMatcher::DEFAULT_PATTERNS, 'my-tool']);

// Or use only your own list:
// $config->blocklists->knownScanners('custom', ['my-tool', 'other-tool']);

$firewall = new Firewall($config);

$requests = [
    ['UA' => 'sqlmap/1.7.8#stable (https://sqlmap.org)', 'expected' => 'BLOCKED'],
    ['UA' => 'Mozilla/5.0 Nikto/2.1.6', 'expected' => 'BLOCKED'],
    ['UA' => 'nuclei/3.0.0 (scan)', 'expected' => 'BLOCKED'],
    ['UA' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'expected' => 'allowed'],
    ['UA' => 'curl/7.85.0', 'expected' => 'allowed'],
    ['UA' => 'Googlebot/2.1 (+http://www.google.com/bot.html)', 'expected' => 'allowed'],
];

foreach ($requests as ['UA' => $ua, 'expected' => $expected]) {
    $request = new ServerRequest('GET', '/api/data', ['User-Agent' => $ua]);
    $result = $firewall->decide($request);
    $actual = $result->isBlocked() ? 'BLOCKED' : 'allowed';
    $status = $actual === $expected ? '✓' : '✗';
    echo "{$status}  {$actual}  (UA: {$ua})\n";
}
