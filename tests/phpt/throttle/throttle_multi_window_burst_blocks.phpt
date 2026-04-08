--TEST--
Phirewall: multi-window throttle enforces burst limit and blocks on 3rd request
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
// Burst limit: 2 per 10s, sustained: 100 per 60s
$config->throttles->multi('api', [10 => 2, 60 => 100], KeyExtractors::ip());

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$serverParams = ['REMOTE_ADDR' => '1.2.3.4'];

$response = $middleware->process(phpt_request('GET', '/', $serverParams), $handler);
echo 'request=1 status=' . $response->getStatusCode() . "\n";

$response = $middleware->process(phpt_request('GET', '/', $serverParams), $handler);
echo 'request=2 status=' . $response->getStatusCode() . "\n";

$response = $middleware->process(phpt_request('GET', '/', $serverParams), $handler);
echo 'request=3 status=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
request=1 status=200
request=2 status=200
request=3 status=429
