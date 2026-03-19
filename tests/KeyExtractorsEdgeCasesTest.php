<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\KeyExtractors;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KeyExtractorsEdgeCasesTest extends TestCase
{
    public function testIpWithMissingRemoteAddr(): void
    {
        $extractor = KeyExtractors::ip();
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertNull($extractor($serverRequest));
    }

    public function testIpWithEmptyRemoteAddr(): void
    {
        $extractor = KeyExtractors::ip();
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '']);

        $this->assertNull($extractor($serverRequest));
    }

    public function testIpReturnsString(): void
    {
        $extractor = KeyExtractors::ip();
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.1']);

        $this->assertSame('192.168.1.1', $extractor($serverRequest));
    }

    public function testMethodUppercases(): void
    {
        $extractor = KeyExtractors::method();
        $serverRequest = new ServerRequest('get', '/');

        $this->assertSame('GET', $extractor($serverRequest));
    }

    public function testMethodPost(): void
    {
        $extractor = KeyExtractors::method();
        $serverRequest = new ServerRequest('POST', '/');

        $this->assertSame('POST', $extractor($serverRequest));
    }

    public function testPathReturnsSlashForEmpty(): void
    {
        $extractor = KeyExtractors::path();
        $serverRequest = new ServerRequest('GET', '');

        $result = $extractor($serverRequest);
        $this->assertSame('/', $result);
    }

    public function testPathReturnsActualPath(): void
    {
        $extractor = KeyExtractors::path();
        $serverRequest = new ServerRequest('GET', '/api/v1/users');

        $this->assertSame('/api/v1/users', $extractor($serverRequest));
    }

    public function testHeaderReturnsNullWhenMissing(): void
    {
        $extractor = KeyExtractors::header('X-Custom');
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertNull($extractor($serverRequest));
    }

    public function testHeaderReturnsValue(): void
    {
        $extractor = KeyExtractors::header('X-Api-Key');
        $serverRequest = new ServerRequest('GET', '/', ['X-Api-Key' => 'secret123']);

        $this->assertSame('secret123', $extractor($serverRequest));
    }

    public function testUserAgentIsHeaderAlias(): void
    {
        $extractor = KeyExtractors::userAgent();
        $serverRequest = new ServerRequest('GET', '/', ['User-Agent' => 'TestBot/1.0']);

        $this->assertSame('TestBot/1.0', $extractor($serverRequest));
    }

    public function testUserAgentReturnsNullWhenMissing(): void
    {
        $extractor = KeyExtractors::userAgent();
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertNull($extractor($serverRequest));
    }
}
