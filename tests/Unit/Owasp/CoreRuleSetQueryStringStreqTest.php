<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetQueryStringStreqTest extends TestCase
{
    public function testQueryStringExactMatchBlocks(): void
    {
        $rulesText = 'SecRule QUERY_STRING "@streq token=abc123" "id:200202,phase:2,deny,msg:\'Block wrong token\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $reqNo = new ServerRequest('GET', '/path?token=zzz');
        $reqYes = new ServerRequest('GET', '/path?token=abc123');

        $this->assertNull($coreRuleSet->match($reqNo));
        $this->assertSame(200202, $coreRuleSet->match($reqYes));
    }
}
