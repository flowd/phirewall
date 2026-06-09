<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Preset;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class PresetsTest extends TestCase
{
    public function testScannerBlockingBlocksKnownToolsAndSuspiciousHeaders(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::scannerBlocking()));

        $scanner = $firewall->decide($this->request('GET', '/')->withHeader('User-Agent', 'sqlmap/1.7'));
        $this->assertSame(Outcome::BLOCKED, $scanner->outcome);
        $this->assertSame('preset.scanner.known-tools', $scanner->rule);

        // A request missing the standard browser Accept headers is suspicious.
        $bareUserAgent = $this->request('GET', '/')->withHeader('User-Agent', 'Mozilla/5.0');
        $suspicious = $firewall->decide($bareUserAgent);
        $this->assertSame(Outcome::BLOCKED, $suspicious->outcome);
        $this->assertSame('preset.scanner.suspicious-headers', $suspicious->rule);

        $this->assertTrue($firewall->decide($this->browserRequest('/'))->isPass());
    }

    public function testSensitivePathBlockingBlocksProbesButAllowsNormalPaths(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::sensitivePathBlocking()));

        foreach (['/.git/config', '/.svn/entries', '/.env', '/.env.production', '/.aws/credentials', '/.htpasswd', '/.htaccess', '/.DS_Store'] as $path) {
            $this->assertSame(
                Outcome::BLOCKED,
                $firewall->decide($this->browserRequest($path))->outcome,
                sprintf('Probe for %s must be blocked', $path),
            );
        }

        foreach (['/', '/index.html', '/api/users', '/.environment', '/environment'] as $path) {
            $this->assertTrue(
                $firewall->decide($this->browserRequest($path))->isPass(),
                sprintf('Legitimate path %s must pass', $path),
            );
        }
    }

    public function testSensitivePathBlockingBlocksNestedAndTrailingEvasions(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::sensitivePathBlocking()));

        // Anchored regex entries block nesting, trailing slashes, and doubled
        // slashes: the exact evasions a PATH_EXACT match would have let through.
        $evasions = [
            '/x/.htpasswd',
            '/app/.aws/credentials',
            '/nested/dir/.htaccess',
            '/sub/.DS_Store',
            '/.htpasswd/',
            '/dir//.htpasswd',
        ];
        foreach ($evasions as $evasion) {
            $this->assertSame(
                Outcome::BLOCKED,
                $firewall->decide($this->browserRequest($evasion))->outcome,
                sprintf('Nested/trailing evasion %s must be blocked', $evasion),
            );
        }
    }

    public function testPresetsAreReturnedAsFreshInstances(): void
    {
        $this->assertNotSame(Presets::scannerBlocking(), Presets::scannerBlocking());

        $cache = new InMemoryCache();
        $configA = (new Config($cache))->combine(Presets::scannerBlocking());
        $configB = (new Config($cache))->combine(Presets::scannerBlocking());
        $this->assertNotSame($configA, $configB);
        $this->assertNotSame($configA->blocklists, $configB->blocklists);
    }

    public function testPortableAccessorsExposeNamespacedRules(): void
    {
        $this->assertSame(
            ['preset.scanner.known-tools', 'preset.scanner.suspicious-headers'],
            array_column(Presets::scannerBlocking()->toArray()['blocklists'], 'name'),
        );

        $this->assertSame(
            ['preset.sensitive-path.probes'],
            array_column(Presets::sensitivePathBlocking()->toArray()['patternBlocklists'], 'name'),
        );
    }

    public function testPresetPortableRoundTripsAsSignedTransport(): void
    {
        $secretKey = random_bytes(32);
        $portable = Presets::scannerBlocking();

        $restored = PortableConfig::loadSigned($portable->toSignedJson($secretKey), $secretKey);
        $this->assertSame($portable->toArray(), $restored->toArray());
    }

    public function testVersionAndNamesAreExposed(): void
    {
        $this->assertSame('1.0.0', Presets::VERSION);
        $this->assertSame(Presets::VERSION, Presets::version());
        $this->assertSame(
            [
                Presets::SCANNER_BLOCKING,
                Presets::SENSITIVE_PATH_BLOCKING,
            ],
            Presets::names(),
        );
    }

    public function testPortableByNameResolvesEveryShippedPreset(): void
    {
        foreach (Presets::names() as $name) {
            $portable = Presets::get($name);
            $schema = $portable->toArray();
            $hasRules = $schema['safelists'] !== []
                || $schema['blocklists'] !== []
                || $schema['throttles'] !== []
                || $schema['fail2bans'] !== []
                || $schema['allow2bans'] !== []
                || $schema['tracks'] !== []
                || $schema['patternBlocklists'] !== [];
            $this->assertTrue($hasRules, sprintf('Preset "%s" must define at least one rule', $name));
        }
    }

    public function testPortableByNameRejectsUnknownPreset(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Presets::get('does-not-exist');
    }

    public function testConfigByNameMatchesNamedFactory(): void
    {
        $cache = new InMemoryCache();
        $byName = (new Config($cache))->combine(Presets::get(Presets::SCANNER_BLOCKING));
        $this->assertSame(
            array_keys((new Config($cache))->combine(Presets::scannerBlocking())->blocklists->rules()),
            array_keys($byName->blocklists->rules()),
        );
    }

    public function testPresetsComposeWithEachOtherAndUserConfig(): void
    {
        $cache = new InMemoryCache();

        $userConfig = new Config($cache);
        $userConfig->safelists->add('internal', static fn($request): bool => $request->getHeaderLine('X-Internal') === 'yes');

        $effective = Config::compose(
            (new Config($cache))->combine(Presets::scannerBlocking(), Presets::sensitivePathBlocking()),
            $userConfig,
        );
        $firewall = new Firewall($effective);

        // Scanner preset rule still fires.
        $this->assertSame(
            Outcome::BLOCKED,
            $firewall->decide($this->request('GET', '/')->withHeader('User-Agent', 'nikto'))->outcome,
        );
        // Sensitive-path preset rule still fires.
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($this->browserRequest('/.git/config'))->outcome);
        // The user's safelist short-circuits everything else.
        $internal = $this->browserRequest('/.git/config')->withHeader('X-Internal', 'yes');
        $this->assertSame(Outcome::SAFELISTED, $firewall->decide($internal)->outcome);
    }

    public function testUserOverrideReplacesPresetRuleByName(): void
    {
        $cache = new InMemoryCache();

        // A later layer redefining a preset rule by the same name replaces it
        // in place rather than adding a second rule.
        $relaxed = new Config($cache);
        $relaxed->blocklists->add('preset.scanner.suspicious-headers', static fn($request): bool => false);

        $effective = (new Config($cache))->combine(Presets::scannerBlocking())->mergedWith($relaxed);
        $this->assertSame(
            ['preset.scanner.known-tools', 'preset.scanner.suspicious-headers'],
            array_keys($effective->blocklists->rules()),
        );

        $firewall = new Firewall($effective);

        // The known-tools rule is untouched and still blocks a scanner User-Agent.
        $this->assertSame(
            Outcome::BLOCKED,
            $firewall->decide($this->request('GET', '/')->withHeader('User-Agent', 'sqlmap/1.7'))->outcome,
        );

        // The overridden suspicious-headers rule no longer blocks a header-less request.
        $this->assertTrue($firewall->decide($this->request('GET', '/'))->isPass());
    }

    private function request(string $method, string $path, string $ip = '203.0.113.1'): ServerRequest
    {
        return new ServerRequest($method, $path, [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function browserRequest(string $path): ServerRequest
    {
        return $this->request('GET', $path)
            ->withHeader('User-Agent', 'Mozilla/5.0')
            ->withHeader('Accept', 'text/html')
            ->withHeader('Accept-Language', 'en')
            ->withHeader('Accept-Encoding', 'gzip');
    }
}
