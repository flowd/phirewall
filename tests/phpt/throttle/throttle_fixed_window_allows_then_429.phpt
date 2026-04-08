--TEST--
Phirewall: fixed-window throttle allows limit requests then returns 429 with Retry-After
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;

$fakeClock = new FakeClock(1_200_000_000.0);
$cache = new InMemoryCache($fakeClock);
$config = new Config($cache, clock: $fakeClock);
$config->throttles->add('limit', 3, 60, KeyExtractors::ip());

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$serverParams = ['REMOTE_ADDR' => '1.2.3.4'];

for ($i = 1; $i <= 3; $i++) {
    $response = $middleware->process(phpt_request('GET', '/', $serverParams), $handler);
    echo 'request=' . $i . ' status=' . $response->getStatusCode() . "\n";
}

$response = $middleware->process(phpt_request('GET', '/', $serverParams), $handler);
echo 'request=4 status=' . $response->getStatusCode() . "\n";
echo 'retry-after=' . $response->getHeaderLine('Retry-After') . "\n";
?>
--EXPECTF--
request=1 status=200
request=2 status=200
request=3 status=200
request=4 status=429
retry-after=%d
