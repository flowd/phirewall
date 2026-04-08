--TEST--
Phirewall: known scanner ruleset blocks sqlmap user-agent (403)
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->blocklists->knownScanners('scanners');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$response = $middleware->process(phpt_request('GET', '/', [], ['User-Agent' => 'sqlmap/1.7']), $handler);
echo 'status=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
status=403
