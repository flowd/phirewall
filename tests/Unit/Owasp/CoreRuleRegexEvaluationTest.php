<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\Operator\RegexEvaluator;
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

        $evaluator = new RegexEvaluator($rule->operatorArgument);
        $this->assertTrue($evaluator->evaluate(['$x(bar);']));
    }

    /**
     * Regression: CRS 942510 ("SQLi bypass attempt by ticks or backticks detected") wraps
     * its alternation in literal backticks. A previous auto-delimiter heuristic treated those
     * backticks as PCRE delimiters, collapsing the regex to its inner body and matching
     * essentially every normal HTTP value.
     */
    public function testRule942510PatternRequiresLiteralBackticksAroundContent(): void
    {
        $pattern = '`(?:[\s\x0b\(\)\+\-0-9<=@-Z_a-\{\}]{2,29}|(?:[\+/-9A-Za-z]{4})+(?:(?:[\+/-9A-Za-z]{2}=|[\+/-9A-Za-z]{3})=)?)`';
        $evaluator = new RegexEvaluator($pattern);

        // Plain HTTP values without backticks must NOT match.
        $this->assertFalse($evaluator->evaluate(['hello world']));
        $this->assertFalse($evaluator->evaluate(['/some/path']));
        $this->assertFalse($evaluator->evaluate(['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)']));
        $this->assertFalse($evaluator->evaluate(['admin']));
        $this->assertFalse($evaluator->evaluate(['']));

        // Values that DO contain the backtick-wrapped SQL fragment must match.
        $this->assertTrue($evaluator->evaluate(['SELECT * FROM `users` WHERE id=1']));
        $this->assertTrue($evaluator->evaluate(['x=`abcd`']));
    }
}
