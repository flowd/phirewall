--TEST--
Phirewall: fail2ban counts pre-handler failures and bans IP once threshold is reached
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;

$clock = new FakeClock();
$config = new Config(new InMemoryCache($clock));
$config->fail2ban->add(
    'login',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn($request) => $request->getHeaderLine('X-Auth-Failed') === '1',
    key: KeyExtractors::ip(),
);

$middleware = phpt_middleware($config);
$handler    = phpt_handler();

// Requests 1–2: filter matches, failure counter increments to 1, 2.
// count >= threshold (3) is false for both, so each request passes through.
for ($index = 1; $index <= 2; $index++) {
    $request  = phpt_request('POST', '/login', ['REMOTE_ADDR' => '1.2.3.4'], ['X-Auth-Failed' => '1']);
    $response = $middleware->process($request, $handler);
    echo 'failure[' . $index . ']=' . $response->getStatusCode() . "\n";
}

// Request 3 (with failure header): count reaches 3, 3 >= 3 → IP banned, request blocked.
$request  = phpt_request('POST', '/login', ['REMOTE_ADDR' => '1.2.3.4'], ['X-Auth-Failed' => '1']);
$response = $middleware->process($request, $handler);
echo 'trigger_ban=' . $response->getStatusCode() . "\n";

// Request 4 (no failure header): IP ban key is present → still blocked.
$request  = phpt_request('GET', '/', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $handler);
echo 'still_banned=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
failure[1]=200
failure[2]=200
trigger_ban=403
still_banned=403
