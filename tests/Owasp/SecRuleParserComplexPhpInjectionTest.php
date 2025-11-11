<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleParser;
use PHPUnit\Framework\TestCase;

final class SecRuleParserComplexPhpInjectionTest extends TestCase
{
    public function testParsesOwaspCrsRule933210(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = <<<RULE
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@rx (?:\((?:.+\)(?:[\"'][\-0-9A-Z_a-z]+[\"'])?\(.+|[^\)]*string[^\)]*\)[\s\x0b\"'\-\.0-9A-\[\]_a-\{\}]+\([^\)]*)|(?:\[[0-9]+\]|\{[0-9]+\}|\$[^\(\),\./;\\]+|[\"'][\-0-9A-Z\\_a-z]+[\"'])\(.+)\);" \
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

        $rule = $secRuleParser->parseLine($line);
        $this->assertNotNull($rule, 'Rule 933210 should be parsed as valid');
        $this->assertSame(933210, $rule->id);
        $this->assertSame('@rx', strtolower($rule->operator));
        $this->assertSame([
            'REQUEST_COOKIES',
            'REQUEST_COOKIES_NAMES',
            'REQUEST_FILENAME',
            'ARGS_NAMES',
            'ARGS',
            'XML:/*',
        ], $rule->variables);
        $this->assertTrue($rule->actions['deny'] ?? false, 'block should map to deny');
        $this->assertSame('PHP Injection Attack: Variable Function Call Found', $rule->actions['msg'] ?? null);
        $this->assertStringContainsString('(?:\(', $rule->operatorArgument);
        $this->assertStringEndsWith(');', $rule->operatorArgument);
    }
}
