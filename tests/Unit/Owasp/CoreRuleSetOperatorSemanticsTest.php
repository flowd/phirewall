<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetOperatorSemanticsTest extends TestCase
{
    public function testRequestUriStartsEndsContainsCaseInsensitive(): void
    {
        $rulesText = implode("\n", [
            // startswith (case-insensitive)
            'SecRule REQUEST_URI "@startswith /AdMin" "id:800101,phase:2,deny,msg:\'Starts with admin\'"',
            // beginswith alias (case-insensitive)
            'SecRule REQUEST_URI "@beginswith /Api" "id:800102,phase:2,deny,msg:\'Begins with api\'"',
            // endswith (case-insensitive)
            'SecRule REQUEST_URI "@endswith .PHP" "id:800103,phase:2,deny,msg:\'Ends with .php\'"',
            // contains (case-insensitive)
            'SecRule REQUEST_URI "@contains SeCrEt" "id:800104,phase:2,deny,msg:\'Contains secret\'"',
        ]);
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $this->assertSame(800101, $coreRuleSet->match(new ServerRequest('GET', '/admin/panel')));
        $this->assertSame(800102, $coreRuleSet->match(new ServerRequest('GET', '/api/v1/users')));
        $this->assertSame(800103, $coreRuleSet->match(new ServerRequest('GET', '/index.php')));
        $this->assertSame(800104, $coreRuleSet->match(new ServerRequest('GET', '/foo/SECRET/bar')));

        // Negative checks
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/user/admin'))); // does not start with /admin
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/apx/v1'))); // does not begin with /api
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/index.php7'))); // does not end with .php
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/foo/SECRT/bar'))); // no 'secret' substring present
    }

    public function testRequestMethodStreqAndContainsCaseInsensitive(): void
    {
        $rulesText = implode("\n", [
            'SecRule REQUEST_METHOD "@streq post" "id:800201,phase:2,deny"',
            'SecRule REQUEST_METHOD "@contains os" "id:800202,phase:2,deny"',
        ]);
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        // First matching rule wins (streq), then after disabling it, contains should match
        $this->assertSame(800201, $coreRuleSet->match(new ServerRequest('POST', '/anything')));
        $coreRuleSet->disable(800201);
        $this->assertSame(800202, $coreRuleSet->match(new ServerRequest('POST', '/anything')));

        // negatives
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/anything')));
    }

    public function testRequestHeadersValuesAndNamesCaseInsensitive(): void
    {
        $rulesText = implode("\n", [
            // Match against header values (contains)
            'SecRule REQUEST_HEADERS "@contains evil" "id:800301,phase:2,deny"',
            // Match against header names (contains)
            'SecRule REQUEST_HEADERS_NAMES "@contains content-type" "id:800302,phase:2,deny"',
        ]);
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $req = new ServerRequest('GET', '/anything');
        $req = $req->withHeader('X-Test', 'EVIL-PAYLOAD')->withHeader('Content-Type', 'text/plain');

        $this->assertSame(800301, $coreRuleSet->match($req));

        // Disable first to test next rule in isolation
        $coreRuleSet->disable(800301);
        $this->assertSame(800302, $coreRuleSet->match($req));

        // Negative: different header set should not match when rules enabled respectively
        $coreRuleSet->enable(800301);
        $coreRuleSet->disable(800302);

        $serverRequest = (new ServerRequest('GET', '/'))->withHeader('X-Test', 'benign');
        $this->assertNull($coreRuleSet->match($serverRequest));
    }
}
