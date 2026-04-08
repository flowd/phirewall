--TEST--
Phirewall: suspicious headers rule blocks request missing Accept header (403) and allows full browser headers (200)
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->blocklists->suspiciousHeaders('headers');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$blockedResponse = $middleware->process(phpt_request('GET', '/', [], []), $handler);
echo 'no-accept status=' . $blockedResponse->getStatusCode() . "\n";

$allowedResponse = $middleware->process(
    phpt_request('GET', '/', [], [
        'Accept' => 'text/html',
        'Accept-Language' => 'en-US',
        'Accept-Encoding' => 'gzip, deflate',
    ]),
    $handler,
);
echo 'full-headers status=' . $allowedResponse->getStatusCode() . "\n";
?>
--EXPECT--
no-accept status=403
full-headers status=200
