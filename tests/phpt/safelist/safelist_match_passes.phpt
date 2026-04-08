--TEST--
Phirewall: safelisted request bypasses blocklist and returns 200
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->safelists->add('health', fn($r) => $r->getUri()->getPath() === '/health');
$config->blocklists->add('block-all', fn() => true);

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$response = $middleware->process(phpt_request('GET', '/health'), $handler);
echo 'status=' . $response->getStatusCode() . "\n";
echo 'handler=' . $response->getHeaderLine('X-Handler') . "\n";
?>
--EXPECT--
status=200
handler=ok
