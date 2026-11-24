<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Http;

use Flowd\Phirewall\Http\PathNormalizer;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PathNormalizerTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, bool}> raw path, normalised path, ambiguous
     */
    public static function paths(): iterable
    {
        // Baseline
        yield 'empty is root' => ['', '/', false];
        yield 'root' => ['/', '/', false];
        yield 'plain path' => ['/admin/x', '/admin/x', false];
        yield 'trailing slash kept' => ['/admin/', '/admin/', false];
        yield 'case kept' => ['/Admin/.ENV', '/Admin/.ENV', false];
        yield 'plus is not a space' => ['/a+b', '/a+b', false];
        yield 'path parameter kept' => ['/admin;jsessionid=abc/x', '/admin;jsessionid=abc/x', false];

        // Percent-decoding: one pass, mixed-case hex, invalid sequences literal
        yield 'encoded dot lowercase' => ['/%2eenv', '/.env', false];
        yield 'encoded dot uppercase' => ['/%2Eenv', '/.env', false];
        yield 'encoded dot in directory' => ['/%2egit/config', '/.git/config', false];
        yield 'encoded letter' => ['/%61dmin/x', '/admin/x', false];
        yield 'mixed-case hex' => ['/%4a%4A%4b', '/JJK', false];
        yield 'encoded space' => ['/my%20file', '/my file', false];
        yield 'multibyte UTF-8' => ['/caf%C3%A9', '/café', false];
        yield 'double encoding decoded once' => ['/%252eenv', '/%2eenv', false];
        yield 'double-encoded dot-dot is no dot-segment' => ['/%252e%252e/admin', '/%2e%2e/admin', false];
        yield 'invalid hex stays literal' => ['/%zz/x', '/%zz/x', false];
        yield 'trailing percent stays literal' => ['/a%', '/a%', false];
        yield 'truncated escape stays literal' => ['/a%2', '/a%2', false];

        // Dot-segments (RFC 3986 section 5.2.4), after decoding
        yield 'single dot' => ['/./admin/x', '/admin/x', true];
        yield 'dot-dot' => ['/a/../b', '/b', true];
        yield 'dot-dot cannot climb above root' => ['/../../x', '/x', true];
        yield 'encoded dot-dot' => ['/a/%2e%2e/b', '/b', true];
        yield 'mixed encoded dot-dot' => ['/a/%2E./b', '/b', true];
        yield 'encoded single dot' => ['/%2e/admin', '/admin', true];
        yield 'final dot keeps directory' => ['/a/.', '/a/', true];
        yield 'final dot-dot keeps directory' => ['/a/b/..', '/a/', true];
        yield 'dot-dot to root' => ['/a/..', '/', true];
        yield 'dots inside a segment are no dot-segment' => ['/a/..b/c./.d', '/a/..b/c./.d', false];

        // Slashes
        yield 'duplicate slashes collapse' => ['/a//b///c', '/a/b/c', true];
        yield 'leading duplicate slashes' => ['//admin', '/admin', true];
        yield 'collapse before dot-segment removal' => ['/admin//../public', '/public', true];
        yield 'encoded slash is a separator' => ['/a%2Fb', '/a/b', true];
        yield 'encoded slash traversal' => ['/public%2f..%2fadmin', '/admin', true];
        yield 'mixed slash traversal' => ['/public/..%2fadmin', '/admin', true];
        yield 'missing leading slash' => ['admin/x', '/admin/x', true];

        // Backslash: literal, never a separator, but ambiguous
        yield 'backslash literal' => ['/a\\b', '/a\\b', true];
        yield 'backslash dot-dot is not resolved' => ['/admin\\..\\public', '/admin\\..\\public', true];
        yield 'encoded backslash' => ['/a%5Cb', '/a\\b', true];

        // Control characters and invalid UTF-8
        yield 'NUL truncates' => ['/.env%00.png', '/.env', true];
        yield 'NUL before dot-dot' => ['/a/..%00/x', '/', true];
        yield 'newline kept' => ['/a%0Ab', "/a\nb", true];
        yield 'DEL kept' => ['/a%7Fb', "/a\x7Fb", true];
        yield 'invalid UTF-8 re-encoded' => ['/admin/%ff', '/admin/%FF', true];
        yield 'overlong dot stays encoded' => ['/%c0%ae%c0%ae/x', '/%C0%AE%C0%AE/x', true];
        yield 'invalid byte between valid ones' => ['/%C3%A9%80x', '/é%80x', true];
    }

    #[DataProvider('paths')]
    public function testAnalyze(string $raw, string $normalized, bool $ambiguous): void
    {
        $normalizedPath = PathNormalizer::analyze($raw);

        $this->assertSame($raw, $normalizedPath->raw);
        $this->assertSame($normalized, $normalizedPath->normalized);
        $this->assertSame($ambiguous, $normalizedPath->ambiguous, 'ambiguity flag');
        $this->assertSame($normalized, PathNormalizer::normalize($raw));
    }

    #[DataProvider('paths')]
    public function testNormalizedPathIsValidUtf8WithoutNul(string $raw): void
    {
        $normalized = PathNormalizer::normalize($raw);

        $this->assertMatchesRegularExpression('//u', $normalized);
        $this->assertStringNotContainsString("\0", $normalized);
        $this->assertStringStartsWith('/', $normalized);
    }

    #[DataProvider('paths')]
    public function testNormalizationIsIdempotentOnUnambiguousOutput(string $raw): void
    {
        $once = PathNormalizer::normalize($raw);

        // A path that decodes to a literal `%xx` legitimately changes again on a
        // second pass; that is the "decode once" rule, not a defect.
        if (preg_match('/%[0-9A-Fa-f]{2}/', $once) === 1) {
            $this->addToAssertionCount(1);
            return;
        }

        $this->assertSame($once, PathNormalizer::normalize($once));
    }

    public function testEveryByteValueNormalizesToValidUtf8(): void
    {
        for ($byte = 0; $byte < 256; ++$byte) {
            $raw = sprintf('/a%%%02Xb', $byte);
            $normalized = PathNormalizer::normalize($raw);
            $this->assertMatchesRegularExpression('//u', $normalized, $raw);
        }
    }

    public function testFromRequestReadsTheUriPath(): void
    {
        $request = new ServerRequest('GET', 'https://example.com/%2e/%61dmin?x=%2e');

        $normalizedPath = PathNormalizer::fromRequest($request);

        $this->assertSame('/%2e/%61dmin', $normalizedPath->raw);
        $this->assertSame('/admin', $normalizedPath->normalized);
        $this->assertTrue($normalizedPath->ambiguous);
    }

    public function testAnalyzeMemoisesTheLastPath(): void
    {
        $this->assertSame(PathNormalizer::analyze('/memo/%2e'), PathNormalizer::analyze('/memo/%2e'));
        $this->assertSame('/other', PathNormalizer::analyze('/other')->normalized);
    }
}
