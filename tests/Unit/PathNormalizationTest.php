<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Path rules match the normalised request path, so percent-encoded and
 * dot-segment spellings of a path cannot sidestep them.
 */
final class PathNormalizationTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function blockedPaths(): iterable
    {
        // The original reproduction: the first three were blocked, the rest passed.
        foreach (['/.env', '/.git/config', '/admin/x', '/%2eenv', '/%2Eenv', '/%2egit/config', '/%61dmin/x', '/./admin/x'] as $path) {
            yield $path => [$path];
        }

        foreach (['/%2e%2e/.env', '/x/%2e%2e/.git/config', '//.env', '/static/..%2f.env', '/.env%00.png', '/%2E%67it/HEAD', '/public/../admin/x'] as $path) {
            yield $path => [$path];
        }
    }

    #[DataProvider('blockedPaths')]
    public function testSensitivePathPresetAndPathPrefixBlocklistBlockEncodedVariants(string $path): void
    {
        $this->assertSame(Outcome::BLOCKED, $this->bypassFirewall()->decide($this->request($path))->outcome, $path);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function passingPaths(): iterable
    {
        foreach (['/', '/index.php', '/api/users', '/.environment', '/%252eenv', '/%252e%252e/.env-not', '/ADMIN/x', '/public/admin'] as $path) {
            yield $path => [$path];
        }
    }

    #[DataProvider('passingPaths')]
    public function testLegitimatePathsStillPass(string $path): void
    {
        $this->assertTrue($this->bypassFirewall()->decide($this->request($path))->isPass(), $path);
    }

    public function testPathEqualsMatchesEncodedAndDecodedSpellingsOfTheValue(): void
    {
        foreach (['/my%20file', '/my file'] as $configured) {
            $firewall = $this->firewall(PortableConfig::create()->blocklist('file', PortableConfig::filterPathEquals($configured)));
            foreach ([['/my%20file', true], ['/./my%20file', true], ['/my%2520file', false], ['/my%20File', false]] as [$path, $blocked]) {
                $this->assertSame(
                    $blocked ? Outcome::BLOCKED : Outcome::PASS,
                    $firewall->decide($this->request($path))->outcome,
                    sprintf('%s against configured %s', $path, $configured),
                );
            }
        }
    }

    public function testRestrictiveRegexAlsoMatchesTheRawPath(): void
    {
        // A traversal detector written against the raw path keeps working,
        // although normalisation removes the dot-segments it looks for.
        $firewall = $this->firewall(PortableConfig::create()
            ->blocklist('traversal', PortableConfig::filterPathRegex('#\.\./|%2e%2e#i')));

        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->request('/a/../etc/passwd'))->outcome);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->request('/a/%2E%2E/etc/passwd'))->outcome);
        $this->assertTrue($firewall->decide($this->request('/etc/passwd'))->isPass());
    }

    public function testUnicodeRegexIsNotDisabledByInvalidUtf8(): void
    {
        $firewall = $this->firewall(PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathRegex('#^/admin(/|$)#u')));

        // Raw path does not match ^/admin, the decoded one is invalid UTF-8:
        // re-encoding keeps the /u regex working instead of erroring to "no match".
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->request('/%61dmin/%ff'))->outcome);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->request('/%61dmin/%c0%ae'))->outcome);
    }

    /**
     * @return iterable<string, array{string, Outcome}>
     */
    public static function safelistCases(): iterable
    {
        yield 'plain safelisted path' => ['/public/app.css', Outcome::SAFELISTED];
        yield 'unambiguous encoding is still safelisted' => ['/%70ublic/app%20file.css', Outcome::SAFELISTED];
        // Ambiguous paths never match a safelist, whatever they normalise to.
        yield 'dot-dot out of the safelist' => ['/public/../admin/x', Outcome::BLOCKED];
        yield 'mixed encoded slash out of the safelist' => ['/public/..%2fadmin/x', Outcome::BLOCKED];
        yield 'encoded slashes out of the safelist' => ['/public%2f..%2fadmin/x', Outcome::BLOCKED];
        yield 'dot-dot into the safelist' => ['/admin/../public/x', Outcome::BLOCKED];
        yield 'encoded slashes into the safelist' => ['/admin%2f..%2fpublic/x', Outcome::BLOCKED];
        yield 'backslash dot-dot into the safelist' => ['/admin%5c..%5cpublic/x', Outcome::BLOCKED];
        yield 'harmless dot-segment is not safelisted' => ['/public/./app.css', Outcome::PASS];
        yield 'duplicate slash is not safelisted' => ['/public//app.css', Outcome::PASS];
        yield 'NUL is not safelisted' => ['/public/app.css%00', Outcome::PASS];
    }

    #[DataProvider('safelistCases')]
    public function testSafelistPathFiltersNeverMatchAnAmbiguousPath(string $path, Outcome $outcome): void
    {
        foreach ([
            PortableConfig::filterPathPrefix('/public/'),
            PortableConfig::filterPathRegex('#^/public/#'),
        ] as $filter) {
            $firewall = $this->firewall(PortableConfig::create()
                ->safelist('public', $filter)
                ->blocklist('admin', PortableConfig::filterPathPrefix('/admin')));

            $this->assertSame($outcome, $firewall->decide($this->request($path))->outcome, sprintf('%s (%s)', $path, $filter['type']));
        }
    }

    public function testSafelistPathEqualsMatchesUnambiguousEncodings(): void
    {
        $firewall = $this->firewall(PortableConfig::create()
            ->safelist('health', PortableConfig::filterPathEquals('/health'))
            ->blocklist('all', PortableConfig::filterAll()));

        $this->assertSame(Outcome::SAFELISTED, $firewall->decide($this->request('/health'))->outcome);
        $this->assertSame(Outcome::SAFELISTED, $firewall->decide($this->request('/%68ealth'))->outcome);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->request('/x/../health'))->outcome);
    }

    public function testPathKeyedThrottleSharesOneCounterAcrossSpellings(): void
    {
        $extractor = KeyExtractors::path();
        foreach (['/login', '/%6cogin', '/./login', '//login', '/x/%2e%2e/login'] as $path) {
            $this->assertSame('/login', $extractor($this->request($path)), $path);
        }

        $this->assertSame('/', $extractor(new ServerRequest('GET', 'https://example.com')));

        $firewall = $this->firewall(PortableConfig::create()
            ->throttle('login', 2, 60, PortableConfig::keyPath(), scope: PortableConfig::filterPathEquals('/login')));

        $this->assertTrue($firewall->decide($this->request('/login'))->isPass());
        $this->assertTrue($firewall->decide($this->request('/%6cogin'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('/./login'))->outcome);
    }

    public function testPatternBackendLiteralAndRequestRegexEntriesMatchNormalisedPath(): void
    {
        $matcher = new SnapshotBlocklistMatcher(new InMemoryPatternBackend([
            new PatternEntry(PatternKind::PATH_EXACT, '/my%20file'),
            new PatternEntry(PatternKind::PATH_PREFIX, '/admin/'),
            new PatternEntry(PatternKind::REQUEST_REGEX, '#^/secret\?#'),
            new PatternEntry(PatternKind::REQUEST_REGEX, '#^/raw%2e%2e#'),
        ]));

        foreach (['/my%20file', '/./my file', '/%61dmin/x', '/x/../admin/', '/%73ecret?q=1', '/raw%2e%2e'] as $path) {
            $this->assertTrue($matcher->match($this->request($path))->isMatch(), $path);
        }

        foreach (['/my%2520file', '/admin', '/secret', '/raw'] as $path) {
            $this->assertFalse($matcher->match($this->request($path))->isMatch(), $path);
        }
    }

    private function bypassFirewall(): Firewall
    {
        return $this->firewall(
            Presets::sensitivePathBlocking(),
            PortableConfig::create()->blocklist('admin', PortableConfig::filterPathPrefix('/admin')),
        );
    }

    private function firewall(PortableConfig ...$portableConfig): Firewall
    {
        return new Firewall((new Config(new InMemoryCache()))->with(...$portableConfig));
    }

    private function request(string $path): ServerRequest
    {
        // Absolute URI so a path starting with `//` is not parsed as an authority.
        return new ServerRequest('GET', 'https://example.com' . $path, [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.1']);
    }
}
