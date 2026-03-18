<?php

declare(strict_types=1);

/**
 * Example 16: allow2ban -- ban keys after too many requests.
 *
 * allow2ban is the inverse of fail2banSeconds:
 * - fail2banSeconds: only counts filtered "bad" requests (e.g. failed logins), bans after threshold
 * - allow2banSeconds: counts EVERY request for a key, bans after threshold
 *
 * Use allow2ban when you want a "n requests and you're out" policy
 * without needing a separate filter predicate.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

$cache = new InMemoryCache();
$config = new Config($cache);

// Ban any IP that sends more than 100 requests in 60 seconds, for 1 hour.
$config->allow2ban->add(
    name: 'high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip(),
);

// Multiple rules can coexist. E.g., also ban by API key for authenticated routes:
// $config->allow2ban->add('api-key-ban', threshold: 1000, period: 60, banSeconds: 300, key: KeyExtractors::header('X-Api-Key'));

$firewall = new Firewall($config);

// Simulate requests from the same IP
$ip = '203.0.113.42';

for ($i = 1; $i <= 105; ++$i) {
    $request = new ServerRequest('GET', '/api/resource', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    $result = $firewall->decide($request);

    if ($result->isBlocked()) {
        echo "Request {$i}: BLOCKED ({$result->headers['X-Phirewall']})\n";
    } else {
        echo "Request {$i}: allowed\n";
    }
}
