--TEST--
Phirewall: blocklist IP rule blocks 10.0.0.1 (403) but allows 10.0.0.2 (200)
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->blocklists->ip('blocked-ip', '10.0.0.1');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$blockedResponse = $middleware->process(phpt_request('GET', '/', ['REMOTE_ADDR' => '10.0.0.1']), $handler);
echo 'blocked ip status=' . $blockedResponse->getStatusCode() . "\n";

$allowedResponse = $middleware->process(phpt_request('GET', '/', ['REMOTE_ADDR' => '10.0.0.2']), $handler);
echo 'allowed ip status=' . $allowedResponse->getStatusCode() . "\n";
?>
--EXPECT--
blocked ip status=403
allowed ip status=200
