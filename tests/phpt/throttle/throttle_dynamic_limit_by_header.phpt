--TEST--
Phirewall: dynamic limit closure applies different rate limits per X-User-Role header
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
$config->throttles->add(
    'role-limit',
    fn($r) => $r->getHeaderLine('X-User-Role') === 'admin' ? 5 : 2,
    60,
    KeyExtractors::ip()
);

$middleware = phpt_middleware($config);
$handler = phpt_handler();

// Regular user from IP 1.1.1.1 — dynamic limit resolves to 2
$regularParams = ['REMOTE_ADDR' => '1.1.1.1'];
for ($i = 1; $i <= 3; $i++) {
    $response = $middleware->process(phpt_request('GET', '/', $regularParams), $handler);
    echo 'regular request=' . $i . ' status=' . $response->getStatusCode() . "\n";
}

// Admin user from IP 2.2.2.2 — dynamic limit resolves to 5
$adminParams = ['REMOTE_ADDR' => '2.2.2.2'];
$adminHeaders = ['X-User-Role' => 'admin'];
for ($i = 1; $i <= 3; $i++) {
    $response = $middleware->process(phpt_request('GET', '/', $adminParams, $adminHeaders), $handler);
    echo 'admin request=' . $i . ' status=' . $response->getStatusCode() . "\n";
}
?>
--EXPECT--
regular request=1 status=200
regular request=2 status=200
regular request=3 status=429
admin request=1 status=200
admin request=2 status=200
admin request=3 status=200
