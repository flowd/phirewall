--TEST--
Phirewall: response headers enabled adds X-Phirewall and X-Phirewall-Safelist headers
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->enableResponseHeaders();
$config->blocklists->add('block-admin', fn($r) => $r->getUri()->getPath() === '/admin');
$config->safelists->add('health', fn($r) => $r->getUri()->getPath() === '/health');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

// Blocked request should include X-Phirewall and X-Phirewall-Matched
$blocked = $middleware->process(phpt_request('GET', '/admin'), $handler);
echo 'status=' . $blocked->getStatusCode() . "\n";
echo 'x-phirewall=' . $blocked->getHeaderLine('X-Phirewall') . "\n";
echo 'x-phirewall-matched=' . $blocked->getHeaderLine('X-Phirewall-Matched') . "\n";

// Safelisted request should include X-Phirewall-Safelist
$safelisted = $middleware->process(phpt_request('GET', '/health'), $handler);
echo 'status=' . $safelisted->getStatusCode() . "\n";
echo 'x-phirewall-safelist=' . $safelisted->getHeaderLine('X-Phirewall-Safelist') . "\n";
?>
--EXPECT--
status=403
x-phirewall=blocklist
x-phirewall-matched=block-admin
status=200
x-phirewall-safelist=health
