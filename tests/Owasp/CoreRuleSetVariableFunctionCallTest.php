<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetVariableFunctionCallTest extends TestCase
{
    public function testMultilineRule933210FromStringMatchesOnArgs(): void
    {
        $text = <<<'RULE'
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@rx (?:\((?:.+\)(?:[\"'][\-0-9A-Z_a-z]+[\"'])?\(.+|[^\)]*string[^\)]*\)[\s\x0b\"'\-\.0-9A-\[\]_a-\{\}]+\([^\)]*)|(?:\[[0-9]+\]|\{[0-9]+\}|\$[^\(\),\./;\x5c]+|[\"'][\-0-9A-Z\x5c_a-z]+[\"'])\(.+\));" \
    "id:933210,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,t:removeWhitespace,\
    msg:'PHP Injection Attack: Variable Function Call Found',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-injection-php',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-PHP',\
    tag:'capec/1000/152/242',\
    ver:'OWASP_CRS/4.21.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
RULE;
        $coreRuleSet = SecRuleLoader::fromString($text);

        // Craft a request where ARGS contains a simple function call pattern that should match the regex
        $serverRequest = (new ServerRequest('GET', '/'))
            ->withQueryParams(['q' => '$x(bar);']);

        $this->assertSame(933210, $coreRuleSet->match($serverRequest));
    }

    public function testRule933210FromExamplesMatchesOnRequestFilename(): void
    {
        $root = dirname(__DIR__, 2);
        $path = $root . '/examples/owasp_crs_basic/REQUEST-933-APPLICATION-ATTACK-PHP.conf';
        $this->assertFileExists($path);
        $coreRuleSet = SecRuleLoader::fromFile($path);
        $this->assertContains(933210, $coreRuleSet->ids(), 'Expected rule 933210 to be parsed from file');

        // Place function-call looking pattern in the request filename (basename of path)
        $serverRequest = new ServerRequest('GET', '/uploads/(alpha)(bravo);');
        $this->assertSame(933210, $coreRuleSet->match($serverRequest));
    }
}
