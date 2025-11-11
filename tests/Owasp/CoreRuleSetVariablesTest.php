<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetVariablesTest extends TestCase
{
    public function testRequestUriContainsMatchesPathAndQuery(): void
    {
        $rulesText = 'SecRule REQUEST_URI "@contains /admin?x=1" "id:400001,phase:2,deny,msg:\'URI contains\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $req = new ServerRequest('GET', '/admin?x=1');
        $this->assertSame(400001, $coreRuleSet->match($req));

        $reqNo = new ServerRequest('GET', '/admin?x=2');
        $this->assertNull($coreRuleSet->match($reqNo));
    }

    public function testRequestMethodExactMatch(): void
    {
        $rulesText = 'SecRule REQUEST_METHOD "@streq POST" "id:400002,phase:2,deny,msg:\'POST only\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $this->assertSame(400002, $coreRuleSet->match(new ServerRequest('POST', '/')));
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/')));
    }

    public function testQueryStringExactMatch(): void
    {
        $rulesText = 'SecRule QUERY_STRING "@streq a=1&b=2" "id:400003,phase:2,deny,msg:\'Query exact\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $this->assertSame(400003, $coreRuleSet->match(new ServerRequest('GET', '/p?a=1&b=2')));
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/p?a=1&b=3')));
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/p')));
    }

    public function testArgsValuesAndNames(): void
    {
        // Match on value and on name
        $rulesTextValue = 'SecRule ARGS "@contains secret" "id:400004,phase:2,deny,msg:\'ARG value contains\'"';
        $rulesTextName = 'SecRule ARGS "@streq token" "id:400005,phase:2,deny,msg:\'ARG name exact\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesTextValue);
        $setName = SecRuleLoader::fromString($rulesTextName);

        $req = new ServerRequest('POST', '/submit?foo=bar');
        $req = $req->withParsedBody([
            'token' => 'secret',
            'nested' => ['a', 'b'],
        ]);

        // ARGS collects both values and names; value 'secret' should match contains
        $this->assertSame(400004, $coreRuleSet->match($req));
        // ARGS also includes names, so exact match on name 'token' should match
        $this->assertSame(400005, $setName->match($req));
    }

    public function testArgsNamesCoversQueryAndBodyKeys(): void
    {
        $rulesText = 'SecRule ARGS_NAMES "@pm token, other" "id:400006,phase:2,deny,msg:\'Args names pm\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $req = new ServerRequest('POST', '/x?foo=1&bar=2');
        $req = $req->withParsedBody([
            'token' => 'v',
            'z' => 1,
        ]);

        $this->assertSame(400006, $coreRuleSet->match($req));

        $reqNo = new ServerRequest('GET', '/x?foo=1&bar=2');
        $reqNo = $reqNo->withParsedBody([
            'z' => 1,
        ]);
        $this->assertNull($coreRuleSet->match($reqNo));
    }

    public function testRequestHeadersValues(): void
    {
        $rulesText = 'SecRule REQUEST_HEADERS "@contains Mozilla" "id:400007,phase:2,deny,msg:\'UA contains Mozilla\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', ['Mozilla/5.0', 'Extra']);
        $this->assertSame(400007, $coreRuleSet->match($serverRequest));

        $reqNo = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', 'curl/8.0.0');
        $this->assertNull($coreRuleSet->match($reqNo));
    }

    public function testRequestHeadersNames(): void
    {
        $rulesText = 'SecRule REQUEST_HEADERS_NAMES "@contains X-Test" "id:400008,phase:2,deny,msg:\'Header name\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-Test', '1')
            ->withHeader('Another', '2');
        $this->assertSame(400008, $coreRuleSet->match($serverRequest));

        $reqNo = (new ServerRequest('GET', '/'))
            ->withHeader('Something-Else', 'x');
        $this->assertNull($coreRuleSet->match($reqNo));
    }

    public function testRequestCookiesValues(): void
    {
        $rulesText = 'SecRule REQUEST_COOKIES "@contains choco" "id:400009,phase:2,deny,msg:\'Cookie value\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'chocolate']);
        $this->assertSame(400009, $coreRuleSet->match($serverRequest));

        $reqNo = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc']);
        $this->assertNull($coreRuleSet->match($reqNo));
    }

    public function testRequestCookiesNames(): void
    {
        $rulesText = 'SecRule REQUEST_COOKIES_NAMES "@contains session" "id:400010,phase:2,deny,msg:\'Cookie name\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'vanilla']);
        $this->assertSame(400010, $coreRuleSet->match($serverRequest));

        $reqNo = (new ServerRequest('GET', '/'))
            ->withCookieParams(['id' => '1']);
        $this->assertNull($coreRuleSet->match($reqNo));
    }
}
