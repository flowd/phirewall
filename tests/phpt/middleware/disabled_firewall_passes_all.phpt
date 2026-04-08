--TEST--
Phirewall: disabled firewall passes all requests; re-enabled firewall enforces rules
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->blocklists->add('block-all', fn() => true);

$middleware = phpt_middleware($config);
$handler = phpt_handler();

// Firewall disabled: request passes even though blocklist would block it
$config->setEnabled(false);
$response = $middleware->process(phpt_request('GET', '/sensitive'), $handler);
echo 'disabled status=' . $response->getStatusCode() . "\n";

// Firewall re-enabled: blocklist is enforced again
$config->setEnabled(true);
$response = $middleware->process(phpt_request('GET', '/sensitive'), $handler);
echo 'enabled status=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
disabled status=200
enabled status=403
