<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

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
}
