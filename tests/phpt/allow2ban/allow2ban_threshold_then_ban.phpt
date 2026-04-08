--TEST--
Phirewall: allow2ban counts every request and bans IP once threshold is exceeded
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
$config->allow2ban->add(
    'volume',
    threshold: 3,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip(),
);

$middleware = phpt_middleware($config);
$handler    = phpt_handler();

// Requests 1–3: hit counter increments to 1, 2, 3.
// count > threshold (3) is false for all three, so each request passes through.
for ($index = 1; $index <= 3; $index++) {
    $request  = phpt_request('GET', '/', ['REMOTE_ADDR' => '1.2.3.4']);
    $response = $middleware->process($request, $handler);
    echo 'request[' . $index . ']=' . $response->getStatusCode() . "\n";
}

// Request 4: count reaches 4, 4 > 3 → IP banned and request blocked immediately.
$request  = phpt_request('GET', '/', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $handler);
echo 'banned=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
request[1]=200
request[2]=200
request[3]=200
banned=403
