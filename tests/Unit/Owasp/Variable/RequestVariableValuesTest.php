<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Variable;

use Flowd\Phirewall\Owasp\Variable\RequestVariableValues;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testCapsCollectedValuesPerVariableAndFlagsTruncation(): void
    {
        $queryParams = [];
        for ($index = 0; $index < 10; ++$index) {
            $queryParams['k' . $index] = 'v' . $index; // 10 params -> 20 ARGS values (value + name)
        }

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);
        $memo = new RequestVariableValues($request, maxValuesPerCrsVariable: 4);

        $this->assertCount(4, $memo->valuesFor('ARGS'), 'Collected values are capped at the configured limit');
        $this->assertTrue($memo->wasCapped('ARGS'), 'Truncation must be flagged so callers can fail closed');
    }

    public function testDoesNotFlagTruncationWhenWithinCap(): void
    {
        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => '1', 'b' => '2']);
        $memo = new RequestVariableValues($request, maxValuesPerCrsVariable: 100);

        $this->assertCount(4, $memo->valuesFor('ARGS')); // 2 params -> value + name each
        $this->assertFalse($memo->wasCapped('ARGS'), 'A variable within the cap must not be flagged as truncated');
    }

    public function testWasCappedIsFalseForUncollectedVariable(): void
    {
        $memo = new RequestVariableValues(new ServerRequest('GET', '/'), maxValuesPerCrsVariable: 1);

        $this->assertFalse($memo->wasCapped('ARGS'), 'A variable never collected cannot have been capped');
    }

    public function testExplicitLimitOverridesDefault(): void
    {
        $memo = new RequestVariableValues(new ServerRequest('GET', '/'), maxValuesPerCrsVariable: 7);

        $this->assertSame(7, $memo->maxValuesPerCrsVariable());
    }

    /**
     * A non-positive cap would truncate every variable and fail all deny rules closed
     * (silently blocking every request), so it must be rejected at construction.
     */
    #[DataProvider('nonPositiveLimits')]
    public function testRejectsNonPositiveExplicitLimit(int $limit): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RequestVariableValues(new ServerRequest('GET', '/'), maxValuesPerCrsVariable: $limit);
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function nonPositiveLimits(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    public function testDefaultLimitDerivesFromPhpMaxInputVars(): void
    {
        $memo = new RequestVariableValues(new ServerRequest('GET', '/'));

        // The default is twice max_input_vars (ARGS emits value + name per parameter).
        $configured = (int) ini_get('max_input_vars');
        $expected = $configured > 0 ? $configured * 2 : RequestVariableValues::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE;

        $this->assertSame($expected, $memo->maxValuesPerCrsVariable());
        $this->assertSame($expected, RequestVariableValues::defaultMaxValuesPerCrsVariable());
    }
}
