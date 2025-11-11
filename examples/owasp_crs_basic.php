<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

// -----------------------------------------------------------------------------
// OWASP Core Rule Set basic example
// -----------------------------------------------------------------------------
// This example shows how to:
// - Load a few CRS-like rules using SecRuleLoader
// - Include a file-based phrase matcher via @pmFromFile
// - Enable/disable rules programmatically
// - Integrate the rule set with the Phirewall Firewall
// -----------------------------------------------------------------------------

require __DIR__ . '/../vendor/autoload.php';

$coreRuleSet = SecRuleLoader::fromDirectory(__DIR__ . '/owasp_crs_basic');

foreach ($coreRuleSet->ids() as $id) {
//    if ($id !== 933150) {
//        $coreRuleSet->disable($id);
//    }
    $enabled = $coreRuleSet->isEnabled($id) ? 'yes' : 'no';

    fwrite(STDOUT, "Loaded CRS {$id}. Rule is enabled: {$enabled} \n");
}

$config = new Config(new InMemoryCache());
$config->owaspBlocklist('owasp', $coreRuleSet)->enableOwaspDiagnosticsHeader();

// Optional: emit a diagnostics header with the matched OWASP rule id (default OFF)
// $config->enableOwaspDiagnosticsHeader(true);

$firewall = new Firewall($config);

// -----------------------------------------------------------------------------
// Demo: a few synthetic requests to show behavior when run from CLI
// -----------------------------------------------------------------------------
if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    $samples = [
        new ServerRequest('GET', '/foo?base64_decode'), // should match 933150
        new ServerRequest('GET', '/any?foo=(system)(ls);'), // should match 933160
        new ServerRequest('GET', '/ok'),
    ];

    foreach ($samples as $sample) {
        $res = $firewall->decide($sample);
        $uri = (string)$sample->getUri();
        if ($res->isBlocked()) {
            $headerRule = $res->headers['X-Phirewall-Owasp-Rule'] ?? '(n/a)';
            fwrite(STDOUT, sprintf('BLOCKED %s — owasp=%s%s', $uri, $headerRule, PHP_EOL));
        } else {
            fwrite(STDOUT, sprintf('PASS    %s%s', $uri, PHP_EOL));
        }
    }
}

// Returning the configured Firewall instance makes this file composable:
return $firewall;
