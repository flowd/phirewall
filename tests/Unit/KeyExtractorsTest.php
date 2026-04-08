<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KeyExtractorsTest extends TestCase
{
    public function testIpExtractorUsesRemoteAddr(): void
    {
        $extractor = KeyExtractors::ip();
        $req = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
        $this->assertSame('203.0.113.10', $extractor($req));

        $req2 = new ServerRequest('GET', '/');
        $this->assertNull($extractor($req2));
    }

    public function testMethodExtractorUppercases(): void
    {
        $extractor = KeyExtractors::method();
        $serverRequest = new ServerRequest('post', '/');
        $this->assertSame('POST', $extractor($serverRequest));
    }

    public function testPathExtractorReturnsPathOrSlash(): void
    {
        $extractor = KeyExtractors::path();
        $this->assertSame('/', $extractor(new ServerRequest('GET', '')));
        $this->assertSame('/admin', $extractor(new ServerRequest('GET', '/admin')));
    }

    public function testHeaderExtractorAndUserAgent(): void
    {
        $ua = KeyExtractors::userAgent();
        $serverRequest = (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'Mozilla');
        $this->assertSame('Mozilla', $ua($serverRequest));
        $this->assertNull($ua(new ServerRequest('GET', '/')));

        $h = KeyExtractors::header('X-Token');
        $req2 = (new ServerRequest('GET', '/'))->withHeader('X-Token', 'abc');
        $this->assertSame('abc', $h($req2));
        $this->assertNull($h(new ServerRequest('GET', '/')));
    }

    public function testClientIpWithTrustedProxyResolver(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $extractor = KeyExtractors::clientIp($trustedProxyResolver);

        // Direct connection from client, untrusted peer: should return REMOTE_ADDR
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.1']);
        $this->assertSame('198.51.100.1', $extractor($serverRequest));

        // Coming via trusted proxy with XFF chain, last proxy is trusted, client is first in chain
        $req2 = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.5']))
            ->withHeader('X-Forwarded-For', '198.51.100.77, 10.0.0.5');
        $this->assertSame('198.51.100.77', $extractor($req2));

        // All hops trusted -> fallback to REMOTE_ADDR
        $req3 = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.5']))
            ->withHeader('X-Forwarded-For', '10.0.0.3, 10.0.0.5');
        $this->assertSame('10.0.0.5', $extractor($req3));
    }
}
