<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Tests\Owasp\Variable\CountingServerRequest;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetTest extends TestCase
{
    public function testEnableDisableRuleId(): void
    {
        $rulesText = "SecRule REQUEST_URI \"@rx ^/admin\b\" \"id:100001,phase:2,deny,msg:'Block admin path'\"";
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $serverRequest = new ServerRequest('GET', '/admin');
        // Initially enabled -> match
        $this->assertSame(100001, $coreRuleSet->match($serverRequest));

        // Disable rule -> no match
        $coreRuleSet->disable(100001);
        $this->assertNull($coreRuleSet->match($serverRequest));

        // Enable again -> match
        $coreRuleSet->enable(100001);
        $this->assertSame(100001, $coreRuleSet->match($serverRequest));
    }

    public function testIdsReturnsRuleIdsInInsertionOrder(): void
    {
        $rulesText = implode("\n", [
            'SecRule REQUEST_URI "@rx ^/a" "id:100001,phase:2,deny"',
            'SecRule REQUEST_URI "@rx ^/b" "id:100002,phase:2,deny"',
        ]);
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $this->assertSame([100001, 100002], $coreRuleSet->ids());
    }

    public function testOverCapVariableFailsClosed(): void
    {
        // When a deny rule's target variable exceeds the per-variable cap, the dropped
        // portion is un-inspectable, so the rule must fail closed (block) rather than let
        // a payload padded past the cap slip through unevaluated.
        $rulesText = 'SecRule ARGS "@streq needle-beyond-cap" "id:100003,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText, maxValuesPerCrsVariable: 4);

        $queryParams = [];
        for ($index = 0; $index < 10; ++$index) {
            $queryParams['k' . $index] = 'v' . $index; // 10 params -> 20 ARGS values, exceeds the cap of 4
        }

        $queryParams['needle-beyond-cap'] = 'needle-beyond-cap';

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);

        $this->assertSame(100003, $coreRuleSet->match($request), 'An over-cap ARGS request must fail closed');
    }

    public function testRuleStillFiresWhenMatchingValueIsWithinCap(): void
    {
        // Positive control for the cap test: the same operator fires normally when the
        // matching value is within the cap, so the fail-closed case above is meaningful.
        $rulesText = 'SecRule ARGS "@streq needle" "id:100004,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText, maxValuesPerCrsVariable: 100);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'needle']);

        $this->assertSame(100004, $coreRuleSet->match($request));
    }

    public function testCapOnOneVariableDoesNotSuppressRuleTargetingAnother(): void
    {
        // The cap (and its fail-closed) is per variable: padding ARGS past the cap must not
        // prevent a rule that targets a different, un-truncated variable from matching.
        $rulesText = 'SecRule REQUEST_URI "@rx needle-in-uri" "id:100005,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText, maxValuesPerCrsVariable: 4);

        $queryParams = [];
        for ($index = 0; $index < 10; ++$index) {
            $queryParams['k' . $index] = 'v' . $index;
        }

        $request = (new ServerRequest('GET', '/path/needle-in-uri'))->withQueryParams($queryParams);

        $this->assertSame(100005, $coreRuleSet->match($request), 'A rule on an un-capped variable must still match');
    }

    public function testRejectsNonPositiveCapAtConstruction(): void
    {
        // A non-positive cap fails every deny rule closed (blocks all traffic), so building a
        // ruleset with one must fail fast rather than surface as silent blocking on the first request.
        $this->expectException(\InvalidArgumentException::class);

        SecRuleLoader::fromString('SecRule REQUEST_URI "@rx x" "id:100008,phase:2,deny"', maxValuesPerCrsVariable: 0);
    }

    public function testSharesCollectedVariablesAcrossRulesForOneRequest(): void
    {
        // Two rules target ARGS; the shared per-request memo must read the request's query
        // params and parsed body exactly once across both rules, not once per rule.
        $rulesText = implode("\n", [
            'SecRule ARGS "@streq nope-a" "id:100006,phase:2,deny"',
            'SecRule ARGS "@streq nope-b" "id:100007,phase:2,deny"',
        ]);
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $inner = (new ServerRequest('POST', '/?foo=bar'))->withParsedBody(['baz' => 'qux']);
        $request = new CountingServerRequest($inner);

        $this->assertNull($coreRuleSet->match($request), 'Neither rule matches this request');
        $this->assertSame(1, $request->queryParamReads, 'ARGS query params must be derived once across rules');
        $this->assertSame(1, $request->parsedBodyReads, 'ARGS parsed body must be derived once across rules');
    }
}
