--TEST--
Phirewall: inline OWASP SQLi rule blocks matching UNION SELECT request with 403
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

$response = $middleware->process(phpt_request('GET', '/search?q=1+UNION+SELECT+password'), $handler);
echo 'status=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
status=403
