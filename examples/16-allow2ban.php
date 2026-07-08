<?php

declare(strict_types=1);

/**
 * Example 16: allow2ban -- ban keys after too many (matching) requests.
 *
 * allow2ban counts requests for a key and bans once the threshold is reached,
 * letting matching requests pass until then:
 * - without a filter: counts EVERY request (a hard volume cap)
 * - with a filter: counts only requests the filter matches
 *
 * The difference from fail2ban is what happens on a match: fail2ban blocks every
 * match immediately (403), while allow2ban lets matching requests through until
 * the threshold is crossed. Use allow2ban for "n and you're out" policies where
 * the counted requests are themselves legitimate.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

$cache = new InMemoryCache();
$config = new Config($cache);
$config->enableResponseHeaders();

// Ban any IP that sends more than 100 requests in 60 seconds, for 1 hour.
$config->allow2ban->add(
    name: 'high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
);

// With a filter: only count writes to the /api/orders endpoint. Reads and other
// paths are not counted at all, so a client can browse freely but is capped on
// order submissions.
$config->allow2ban->add(
    name: 'order-flood',
    threshold: 3,
    period: 60,
    banSeconds: 3600,
    key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '',
    filter: fn($request): bool => $request->getMethod() === 'POST'
        && $request->getUri()->getPath() === '/api/orders',
);

// Multiple rules can coexist. E.g., also ban by API key for authenticated routes
// — use hashedHeader() so the raw credential never lands in the cache backend
// or the ban registry:
// $config->allow2ban->add('api-key-ban', threshold: 1000, period: 60, banSeconds: 300, key: KeyExtractors::hashedHeader('X-Api-Key'));

$firewall = new Firewall($config);

// Demo 1: the filtered "order-flood" rule. Reads never count; the 3rd POST bans.
echo "=== order-flood (filtered): reads pass, 3rd order submission bans ===\n";
$ip = '203.0.113.7';
$requests = [
    ['GET', '/api/orders'],   // read, not counted
    ['GET', '/api/orders'],   // read, not counted
    ['POST', '/api/orders'],  // order 1
    ['POST', '/api/orders'],  // order 2
    ['POST', '/api/orders'],  // order 3 -> ban
    ['POST', '/api/orders'],  // banned
];
foreach ($requests as [$method, $path]) {
    $request = new ServerRequest($method, $path, [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    $result = $firewall->decide($request);
    $state = $result->isBlocked() ? 'BLOCKED' : 'allowed';
    echo sprintf("  %-4s %-12s => %s\n", $method, $path, $state);
}

echo "\n=== high-volume-ban (no filter): every request counts, 100th bans ===\n";
$volumeIp = '203.0.113.42';
for ($i = 1; $i <= 105; ++$i) {
    $request = new ServerRequest('GET', '/api/resource', [], null, '1.1', ['REMOTE_ADDR' => $volumeIp]);
    $result = $firewall->decide($request);

    if ($result->isBlocked()) {
        echo "Request {$i}: BLOCKED ({$result->headers['X-Phirewall']})\n";
    }
}
