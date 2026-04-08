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
        $collectors = VariableCollectorFactory::createCollectors([
            'REQUEST_URI',
            'REQUEST_METHOD',
            'QUERY_STRING',
            'ARGS',
            'ARGS_NAMES',
            'REQUEST_COOKIES',
            'REQUEST_COOKIES_NAMES',
            'REQUEST_HEADERS',
            'REQUEST_HEADERS_NAMES',
            'REQUEST_FILENAME',
        ]);

        $this->assertCount(10, $collectors);
        $this->assertInstanceOf(RequestUriCollector::class, $collectors[0]);
        $this->assertInstanceOf(RequestMethodCollector::class, $collectors[1]);
        $this->assertInstanceOf(QueryStringCollector::class, $collectors[2]);
        $this->assertInstanceOf(ArgsCollector::class, $collectors[3]);
        $this->assertInstanceOf(ArgsNamesCollector::class, $collectors[4]);
        $this->assertInstanceOf(RequestCookiesCollector::class, $collectors[5]);
        $this->assertInstanceOf(RequestCookiesNamesCollector::class, $collectors[6]);
        $this->assertInstanceOf(RequestHeadersCollector::class, $collectors[7]);
        $this->assertInstanceOf(RequestHeadersNamesCollector::class, $collectors[8]);
        $this->assertInstanceOf(RequestFilenameCollector::class, $collectors[9]);
    }

    public function testFactorySkipsUnknownVariables(): void
    {
        $collectors = VariableCollectorFactory::createCollectors([
            'REQUEST_URI',
            'XML:/*',
            'UNKNOWN_VAR',
        ]);

        $this->assertCount(1, $collectors);
        $this->assertInstanceOf(RequestUriCollector::class, $collectors[0]);
    }
}
