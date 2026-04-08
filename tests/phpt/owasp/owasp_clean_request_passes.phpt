--TEST--
Phirewall: inline OWASP SQLi rule allows clean request with 200
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;

$rules = SecRuleLoader::fromString(
    'SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:\'SQLi\'"'
);

$config = new Config(new InMemoryCache());
$config->blocklists->owasp('sqli', $rules);

$middleware = phpt_middleware($config);
$handler = phpt_handler();

$response = $middleware->process(phpt_request('GET', '/search?q=hello+world'), $handler);
echo 'status=' . $response->getStatusCode() . "\n";
echo 'handler=' . $response->getHeaderLine('X-Handler') . "\n";
?>
--EXPECT--
status=200
handler=ok
