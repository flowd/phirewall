<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Variable;

use Flowd\Phirewall\Owasp\CoreRule;
use Flowd\Phirewall\Owasp\Variable\RequestVariableValues;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RequestVariableValuesTest extends TestCase
{
    public function testCollectsEachDistinctVariableOnlyOnce(): void
    {
        $inner = (new ServerRequest('POST', '/submit?foo=bar'))->withParsedBody(['token' => 'secret']);
        $request = new CountingServerRequest($inner);
        $memo = new RequestVariableValues($request);

        $first = $memo->valuesFor('ARGS');
        $second = $memo->valuesFor('ARGS');

        // Same values returned, but the underlying request was read only once.
        $this->assertSame($first, $second);
        $this->assertContains('bar', $first);
        $this->assertContains('secret', $first);
        $this->assertSame(1, $request->queryParamReads, 'getQueryParams() must be derived once per request');
        $this->assertSame(1, $request->parsedBodyReads, 'getParsedBody() must be derived once per request');
    }

    public function testUnknownVariableYieldsEmptyListAndCaches(): void
    {
        $memo = new RequestVariableValues(new ServerRequest('GET', '/'));

        $this->assertSame([], $memo->valuesFor('UNKNOWN_VAR'));
        // Second call returns the cached empty list as well.
        $this->assertSame([], $memo->valuesFor('UNKNOWN_VAR'));
    }

    public function testCapsCollectedValuesPerVariable(): void
    {
        $queryParams = [];
        for ($index = 0; $index < CoreRule::MAX_VALUES + 50; ++$index) {
            $queryParams['k' . $index] = 'v' . $index;
        }

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);
        $memo = new RequestVariableValues($request);

        $this->assertCount(CoreRule::MAX_VALUES, $memo->valuesFor('ARGS'));
    }
}
