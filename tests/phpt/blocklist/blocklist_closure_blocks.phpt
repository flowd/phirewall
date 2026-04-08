--TEST--
Phirewall: blocklist closure blocks /admin (403) but allows /home (200)
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->blocklists->add('block-admin', fn($request) => $request->getUri()->getPath() === '/admin');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$blockedResponse = $middleware->process(phpt_request('GET', '/admin'), $handler);
echo 'admin status=' . $blockedResponse->getStatusCode() . "\n";

$allowedResponse = $middleware->process(phpt_request('GET', '/home'), $handler);
echo 'home status=' . $allowedResponse->getStatusCode() . "\n";
?>
--EXPECT--
admin status=403
home status=200
