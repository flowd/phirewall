<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleParser;
use PHPUnit\Framework\TestCase;

final class CoreRuleRegexEvaluationTest extends TestCase
{
    public function testRule933210PatternMatchesDollarVarCall(): void
    {
        $text = <<<'RULE'
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@rx (?:\((?:.+\)(?:[\"'][\-0-9A-Z_a-z]+[\"'])?\(.+|[^\)]*string[^\)]*\)[\s\x0b\"'\-\.0-9A-\[\]_a-\{\}]+\([^\)]*)|(?:\[[0-9]+\]|\{[0-9]+\}|\$[^\(\),\./;\\]+|[\"'][\-0-9A-Z\\_a-z]+[\"'])\(.+\));" "id:933210,phase:2,block"
RULE;
        $rule = (new SecRuleParser())->parseLine($text);
        $this->assertNotNull($rule);
        $reflectionMethod = (new \ReflectionClass($rule))->getMethod('ensureRegexDelimiters');
        $reflectionMethod->setAccessible(true);

        $delimited = $reflectionMethod->invoke($rule, $rule->operatorArgument);
        $this->assertIsString($delimited);
        $this->assertSame(1, @preg_match($delimited, '$x(bar);'));
    }
}
