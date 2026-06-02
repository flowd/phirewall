<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\CoreRule;
use Flowd\Phirewall\Owasp\SecRuleLoader;
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

    public function testValuesBeyondCountCapAreNotEvaluated(): void
    {
        // A unique needle placed past the per-variable value cap must not be reachable,
        // bounding per-request work regardless of how many parameters the client sends.
        $rulesText = 'SecRule ARGS "@streq needle-beyond-cap" "id:100003,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $queryParams = [];
        for ($index = 0; $index < CoreRule::MAX_VALUES; ++$index) {
            $queryParams['k' . $index] = 'v' . $index;
        }

        $queryParams['needle-beyond-cap'] = 'needle-beyond-cap';

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);

        $this->assertNull($coreRuleSet->match($request));
    }
}
