--TEST--
Phirewall: fail2ban blocks every filter match and bans IP once threshold is reached
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;

$clock = new FakeClock();
$config = new Config(new InMemoryCache($clock));
$config->fail2ban->add(
    'scanner-probes',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/.env'),
);

$middleware = phpt_middleware($config);
$handler    = phpt_handler();

// Requests 1–2: filter matches, match counter increments to 1, 2.
// count >= threshold (3) is false for both, but every match is blocked (403).
for ($index = 1; $index <= 2; $index++) {
    $request  = phpt_request('GET', '/.env', ['REMOTE_ADDR' => '1.2.3.4']);
    $response = $middleware->process($request, $handler);
    echo 'probe[' . $index . ']=' . $response->getStatusCode() . "\n";
}

// Request 3 (matching): count reaches 3, 3 >= 3 → IP banned, request blocked.
$request  = phpt_request('GET', '/.env', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $handler);
echo 'trigger_ban=' . $response->getStatusCode() . "\n";

// Request 4 (non-matching path): IP ban key is present → still blocked.
$request  = phpt_request('GET', '/', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $handler);
echo 'still_banned=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
probe[1]=403
probe[2]=403
trigger_ban=403
still_banned=403
