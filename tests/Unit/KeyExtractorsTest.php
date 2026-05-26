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

    public function testHashedHeaderReturnsSha256OfRawValue(): void
    {
        $extractor = KeyExtractors::hashedHeader('Authorization');
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer s3cret');

        $this->assertSame(hash('sha256', 'Bearer s3cret'), $extractor($request));
    }

    public function testHashedHeaderReturnsNullWhenHeaderIsMissing(): void
    {
        $extractor = KeyExtractors::hashedHeader('Authorization');

        $this->assertNull($extractor(new ServerRequest('GET', '/')));
    }

    public function testHashedHeaderReturnsNullForEmptyHeaderValue(): void
    {
        // An empty-string header must collapse to null — same contract as
        // header() — so a present-but-blank header doesn't fingerprint the
        // empty string and produce a spurious bucket.
        $extractor = KeyExtractors::hashedHeader('Authorization');
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', '');

        $this->assertNull($extractor($request));
    }

    public function testHashedHeaderJoinsMultipleHeaderValuesBeforeHashing(): void
    {
        // PSR-7's getHeaderLine joins multiple header values with ", ". The
        // fingerprint is over the joined string — pin this so a refactor to
        // getHeader()[0] would surface as a test failure rather than silently
        // changing every stored bucket key.
        $extractor = KeyExtractors::hashedHeader('X-Api-Key');
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('X-Api-Key', 'first')
            ->withAddedHeader('X-Api-Key', 'second');

        $this->assertSame(hash('sha256', 'first, second'), $extractor($request));
    }

    public function testHashedHeaderLookupIsCaseInsensitive(): void
    {
        // PSR-7 header names are case-insensitive on lookup. An extractor
        // configured for "Authorization" must match a request that carries
        // "authorization" so deployments behind a case-folding proxy don't
        // suddenly produce a different bucket key.
        $extractor = KeyExtractors::hashedHeader('Authorization');
        $request = (new ServerRequest('GET', '/'))->withHeader('authorization', 'Bearer s3cret');

        $this->assertSame(hash('sha256', 'Bearer s3cret'), $extractor($request));
    }

    public function testHashedHeaderIsDeterministic(): void
    {
        // The same input must produce the same fingerprint across calls —
        // otherwise the bucket key would shift between requests for the same
        // client. Trivial guard, cheap to maintain.
        $extractor = KeyExtractors::hashedHeader('Authorization');
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer s3cret');

        $this->assertSame($extractor($request), $extractor($request));
    }

    public function testHashedHeaderFingerprintsExactlyWhatHeaderReturns(): void
    {
        // Parity guard: hashedHeader() must fingerprint the same value that
        // header() returns, against the same request. Catches any future
        // divergence (e.g. one path trims or normalises while the other
        // doesn't) in a single assertion.
        $rawExtractor = KeyExtractors::header('Authorization');
        $hashedExtractor = KeyExtractors::hashedHeader('Authorization');
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer s3cret');

        $rawValue = $rawExtractor($request);
        $this->assertNotNull($rawValue);
        $this->assertSame(hash('sha256', $rawValue), $hashedExtractor($request));
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
