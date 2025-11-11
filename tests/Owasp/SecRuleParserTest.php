<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleParser;
use PHPUnit\Framework\TestCase;

final class SecRuleParserTest extends TestCase
{
    public function testParsesSimpleRxRule(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = "SecRule REQUEST_URI \"@rx admin\" \"id:100000,phase:2,deny,msg:'Block admin'\"";
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule);
        $this->assertSame(100000, $rule->id);
        $this->assertSame(['REQUEST_URI'], $rule->variables);
        $this->assertSame('@rx', $rule->operator);
        $this->assertSame('admin', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesStreqOperator(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule QUERY_STRING "@streq token=abc123" "id:200201,phase:2,deny,msg:\'Exact token required\'"';
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule);
        $this->assertSame(200201, $rule->id);
        $this->assertSame(['QUERY_STRING'], $rule->variables);
        $this->assertSame('@streq', $rule->operator);
        $this->assertSame('token=abc123', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesStartsWithOperator(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_URI "@startswith /admin" "id:300001,phase:2,deny,msg:\'Starts with /admin\'"';
        $rule = $secRuleParser->parseLine($line);
        $this->assertNotNull($rule);
        $this->assertSame(300001, $rule->id);
        $this->assertSame(['REQUEST_URI'], $rule->variables);
        $this->assertSame('@startswith', strtolower($rule->operator));
        $this->assertSame('/admin', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesEndsWithOperator(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_URI "@endswith .php" "id:300002,phase:2,deny,msg:\'Ends with .php\'"';
        $rule = $secRuleParser->parseLine($line);
        $this->assertNotNull($rule);
        $this->assertSame(300002, $rule->id);
        $this->assertSame(['REQUEST_URI'], $rule->variables);
        $this->assertSame('@endswith', strtolower($rule->operator));
        $this->assertSame('.php', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesPmOperatorWithQuotedPhrases(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_URI "@pm admin, \"secret area\" other" "id:300003,phase:2,deny,msg:\'PM list\'"';
        $rule = $secRuleParser->parseLine($line);
        $this->assertNotNull($rule);
        $this->assertSame(300003, $rule->id);
        $this->assertSame(['REQUEST_URI'], $rule->variables);
        $this->assertSame('@pm', strtolower($rule->operator));
        $this->assertSame('admin, "secret area" other', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesActionsWithQuotedValuesAndEmbeddedCommas(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_URI "@contains admin" "id:300001,phase:2,deny,msg:\'Block, admin path\',tag:\'attack,access\'"';
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule, 'Rule should be parsed');
        $this->assertSame(300001, $rule->id);
        $this->assertSame(['REQUEST_URI'], $rule->variables);
        $this->assertSame('@contains', $rule->operator);
        $this->assertSame('admin', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
        $this->assertSame("Block, admin path", $rule->actions['msg'] ?? null);
        $this->assertSame('attack,access', $rule->actions['tag'] ?? null);
    }

    public function testParsesMultipleVariablesAndIgnoresTransforms(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_HEADERS|ARGS "@contains bad" "id:300002,phase:2,deny,t:lowercase,msg:\'Bad content\'"';
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule, 'Rule should be parsed');
        $this->assertSame(300002, $rule->id);
        $this->assertSame(['REQUEST_HEADERS', 'ARGS'], $rule->variables);
        $this->assertSame('@contains', $rule->operator);
        $this->assertSame('bad', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
        // transform token should be captured in actions map or ignored; we only assert it's not breaking parsing
        $this->assertSame('Bad content', $rule->actions['msg'] ?? null);
    }

    public function testParsesContainsOperator(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = 'SecRule REQUEST_METHOD "@contains POST" "id:200001,phase:2,deny,msg:\'Block POST\'"';
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule);
        $this->assertSame(200001, $rule->id);
        $this->assertSame(['REQUEST_METHOD'], $rule->variables);
        $this->assertSame('@contains', $rule->operator);
        $this->assertSame('POST', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false);
    }

    public function testParsesMultilineRule(): void
    {
        $secRuleParser = new SecRuleParser();
        $line = <<<Rule_WRAP
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)<\\?(?:[^x]|x(?:[^m]|m(?:[^l]|l(?:[^\\s\v]|[\\s\v]+[^a-z]|\$)))|\$|php)|\\[[/\\]?php\\]" \\
    "id:933100,\\
    phase:2,\\
    block,\\
    capture,\\
    t:none,\\
    msg:'PHP Injection Attack: PHP Open Tag Found',\\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\\
    tag:'application-multi',\\
    tag:'language-php',\\
    tag:'platform-multi',\\
    tag:'attack-injection-php',\\
    tag:'paranoia-level/1',\\
    tag:'OWASP_CRS',\\
    tag:'OWASP_CRS/ATTACK-PHP',\\
    tag:'capec/1000/152/242',\\
    ver:'OWASP_CRS/4.21.0-dev',\\
    severity:'CRITICAL',\\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
Rule_WRAP;
        $rule = $secRuleParser->parseLine($line);

        $this->assertNotNull($rule);
        $this->assertSame(933100, $rule->id);
        $this->assertSame(['REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES', 'ARGS_NAMES', 'ARGS', 'XML:/*'], $rule->variables);
        $this->assertSame('@rx', strtolower($rule->operator));
        $this->assertStringStartsWith('(?i)<\?', $rule->operatorArgument);
        $this->assertTrue($rule->actions['deny'] ?? false, 'block should map to deny');
        $this->assertSame('PHP Injection Attack: PHP Open Tag Found', $rule->actions['msg'] ?? null);
    }
}
