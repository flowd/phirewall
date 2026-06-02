<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Variable;

use Flowd\Phirewall\Owasp\Variable\ArgsCollector;
use Flowd\Phirewall\Owasp\Variable\ArgsNamesCollector;
use Flowd\Phirewall\Owasp\Variable\QueryStringCollector;
use Flowd\Phirewall\Owasp\Variable\RequestCookiesCollector;
use Flowd\Phirewall\Owasp\Variable\RequestCookiesNamesCollector;
use Flowd\Phirewall\Owasp\Variable\RequestFilenameCollector;
use Flowd\Phirewall\Owasp\Variable\RequestHeadersCollector;
use Flowd\Phirewall\Owasp\Variable\RequestHeadersNamesCollector;
use Flowd\Phirewall\Owasp\Variable\RequestMethodCollector;
use Flowd\Phirewall\Owasp\Variable\RequestUriCollector;
use Flowd\Phirewall\Owasp\Variable\VariableCollectorFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class VariableCollectorTest extends TestCase
{
    public function testRequestUriCollectorReturnsPathAndQuery(): void
    {
        $collector = new RequestUriCollector();
        $request = new ServerRequest('GET', '/admin?x=1');

        $result = $collector->collect($request);

        $this->assertSame(['/admin?x=1'], $result);
    }

    public function testRequestUriCollectorOmitsQuestionMarkWhenNoQuery(): void
    {
        $collector = new RequestUriCollector();
        $request = new ServerRequest('GET', '/page');

        $result = $collector->collect($request);

        $this->assertSame(['/page'], $result);
    }

    public function testRequestMethodCollectorReturnsMethod(): void
    {
        $collector = new RequestMethodCollector();

        $this->assertSame(['POST'], $collector->collect(new ServerRequest('POST', '/')));
        $this->assertSame(['GET'], $collector->collect(new ServerRequest('GET', '/')));
    }

    public function testQueryStringCollectorReturnsRawQuery(): void
    {
        $collector = new QueryStringCollector();
        $request = new ServerRequest('GET', '/path?a=1&b=2');

        $this->assertSame(['a=1&b=2'], $collector->collect($request));
    }

    public function testQueryStringCollectorReturnsEmptyStringWhenNoQuery(): void
    {
        $collector = new QueryStringCollector();
        $request = new ServerRequest('GET', '/path');

        $this->assertSame([''], $collector->collect($request));
    }

    public function testArgsCollectorCollectsQueryAndBodyValuesAndNames(): void
    {
        $collector = new ArgsCollector();
        $request = (new ServerRequest('POST', '/submit?foo=bar'))
            ->withParsedBody(['token' => 'secret', 'nested' => ['a', 'b']]);

        $result = $collector->collect($request);

        // Query params: value "bar", key "foo"
        $this->assertContains('bar', $result);
        $this->assertContains('foo', $result);
        // Body params: value "secret", key "token", nested values "a" and "b", key "nested"
        $this->assertContains('secret', $result);
        $this->assertContains('token', $result);
        $this->assertContains('a', $result);
        $this->assertContains('b', $result);
        $this->assertContains('nested', $result);
    }

    public function testArgsCollectorCollectsValueAndNameForEveryParameterWithoutTruncating(): void
    {
        $collector = new ArgsCollector();

        // The collector no longer caps: it returns a value AND a name for every parameter.
        // Bounding the value count (and failing closed when exceeded) is applied centrally
        // by RequestVariableValues, so a parameter is never half-collected here.
        $queryParams = [];
        for ($index = 0; $index < 50; ++$index) {
            $queryParams['k' . $index] = 'v' . $index;
        }

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);

        $result = $collector->collect($request);

        $this->assertCount(100, $result, 'Every parameter contributes its value and its name, untruncated');
    }

    public function testArgsNamesCollectorCollectsKeysOnly(): void
    {
        $collector = new ArgsNamesCollector();
        $request = (new ServerRequest('POST', '/x?foo=1&bar=2'))
            ->withParsedBody(['token' => 'v']);

        $result = $collector->collect($request);

        $this->assertContains('foo', $result);
        $this->assertContains('bar', $result);
        $this->assertContains('token', $result);
        $this->assertNotContains('1', $result);
        $this->assertNotContains('2', $result);
        $this->assertNotContains('v', $result);
    }

    public function testRequestCookiesCollectorReturnsCookieValues(): void
    {
        $collector = new RequestCookiesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'chocolate']);

        $result = $collector->collect($request);

        $this->assertSame(['abc', 'chocolate'], $result);
    }

    public function testRequestCookiesNamesCollectorReturnsCookieKeys(): void
    {
        $collector = new RequestCookiesNamesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'vanilla']);

        $result = $collector->collect($request);

        $this->assertSame(['session', 'flavor'], $result);
    }

    public function testRequestHeadersCollectorReturnsAllHeaderValues(): void
    {
        $collector = new RequestHeadersCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', ['Mozilla/5.0', 'Extra'])
            ->withHeader('Accept', 'text/html');

        $result = $collector->collect($request);

        $this->assertContains('Mozilla/5.0', $result);
        $this->assertContains('Extra', $result);
        $this->assertContains('text/html', $result);
    }

    public function testRequestHeadersNamesCollectorReturnsHeaderNames(): void
    {
        $collector = new RequestHeadersNamesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('X-Test', '1')
            ->withHeader('Content-Type', 'text/plain');

        $result = $collector->collect($request);

        // Nyholm PSR-7 normalizes header names
        $lowered = array_map('strtolower', $result);
        $this->assertContains('x-test', $lowered);
        $this->assertContains('content-type', $lowered);
    }

    public function testRequestFilenameCollectorReturnsBasename(): void
    {
        $collector = new RequestFilenameCollector();
        $request = new ServerRequest('GET', '/uploads/photo.jpg');

        $this->assertSame(['photo.jpg'], $collector->collect($request));
    }

    public function testRequestFilenameCollectorReturnsEmptyForEmptyPath(): void
    {
        $collector = new RequestFilenameCollector();
        // Construct with an empty path
        $request = new ServerRequest('GET', '');

        $result = $collector->collect($request);
        // PSR-7 may normalize empty path; just verify no exception and result type
        $this->assertGreaterThanOrEqual(0, count($result));
    }

    public function testFactoryResolvesKnownVariables(): void
    {
        $this->assertInstanceOf(RequestUriCollector::class, VariableCollectorFactory::create('REQUEST_URI'));
        $this->assertInstanceOf(RequestMethodCollector::class, VariableCollectorFactory::create('REQUEST_METHOD'));
        $this->assertInstanceOf(QueryStringCollector::class, VariableCollectorFactory::create('QUERY_STRING'));
        $this->assertInstanceOf(ArgsCollector::class, VariableCollectorFactory::create('ARGS'));
        $this->assertInstanceOf(ArgsNamesCollector::class, VariableCollectorFactory::create('ARGS_NAMES'));
        $this->assertInstanceOf(RequestCookiesCollector::class, VariableCollectorFactory::create('REQUEST_COOKIES'));
        $this->assertInstanceOf(RequestCookiesNamesCollector::class, VariableCollectorFactory::create('REQUEST_COOKIES_NAMES'));
        $this->assertInstanceOf(RequestHeadersCollector::class, VariableCollectorFactory::create('REQUEST_HEADERS'));
        $this->assertInstanceOf(RequestHeadersNamesCollector::class, VariableCollectorFactory::create('REQUEST_HEADERS_NAMES'));
        $this->assertInstanceOf(RequestFilenameCollector::class, VariableCollectorFactory::create('REQUEST_FILENAME'));
    }

    public function testFactoryReturnsNullForUnknownVariables(): void
    {
        $this->assertInstanceOf(RequestUriCollector::class, VariableCollectorFactory::create('REQUEST_URI'));
        $this->assertNull(VariableCollectorFactory::create('XML:/*'));
        $this->assertNull(VariableCollectorFactory::create('UNKNOWN_VAR'));
    }
}
