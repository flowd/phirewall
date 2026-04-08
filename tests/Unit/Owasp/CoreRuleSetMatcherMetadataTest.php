<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\CoreRuleSetMatcher;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMatcherMetadataTest extends TestCase
{
    public function testMatchIncludesOwaspRuleIdAndMsgMetadata(): void
    {
        $rulesText = "SecRule REQUEST_URI \"@rx ^/admin\\b\" \"id:400001,phase:2,deny,msg:'Block admin path'\"";
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $serverRequest = new ServerRequest('GET', '/admin');
        $matchResult = $coreRuleSetMatcher->match($serverRequest);

        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('owasp', $matchResult->source());
        $meta = $matchResult->metadata();
        $this->assertSame(400001, $meta['owasp_rule_id'] ?? null);
        $this->assertSame('Block admin path', $meta['msg'] ?? null);
    }
}
