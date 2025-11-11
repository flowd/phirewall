<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMethodContainsTest extends TestCase
{
    public function testMethodContainsBlocksPost(): void
    {
        $rulesText = 'SecRule REQUEST_METHOD "@contains POST" "id:200100,phase:2,deny,msg:\'Block POST methods\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $reqPost = new ServerRequest('POST', '/anything');
        $reqGet = new ServerRequest('GET', '/anything');

        $this->assertSame(200100, $coreRuleSet->match($reqPost));
        $this->assertNull($coreRuleSet->match($reqGet));
    }
}
