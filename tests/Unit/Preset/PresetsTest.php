<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Preset;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RecordedSignal;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class PresetsTest extends TestCase
{
    public function testApiRateLimitingThrottlesApiTrafficPerClient(): void
    {
        // A frozen FakeClock keeps all requests inside the 1-second burst window
        // so the assertion can never straddle a window boundary on slow CI. The
        // clock drives the cache (where the sliding window is computed) and the
        // Config, so timing is fully deterministic.
        $clock = new FakeClock();
        $firewall = new Firewall(
            (new Config(new InMemoryCache($clock), null, $clock))->combine(Presets::apiRateLimiting()),
        );

        // The burst window allows 20 requests/second on /api.
        for ($i = 1; $i <= 20; ++$i) {
            $this->assertTrue(
                $firewall->decide($this->apiRequest())->isPass(),
                sprintf('Request %d within the burst limit should pass', $i),
            );
        }

        // At least one of the next requests must trip the throttle.
        $throttled = false;
        for ($i = 21; $i <= 25; ++$i) {
            if ($firewall->decide($this->apiRequest())->outcome === Outcome::THROTTLED) {
                $throttled = true;
                break;
            }
        }

        $this->assertTrue($throttled, 'Requests beyond the burst limit must be throttled');
    }

    public function testApiRateLimitingLeavesNonApiTrafficUntouched(): void
    {
        // Deterministic clock so all 50 requests fall in one window: if a
        // regression ever counted non-/api traffic, the throttle would trip here
        // rather than being hidden by a window boundary on slow CI.
        $clock = new FakeClock();
        $firewall = new Firewall(
            (new Config(new InMemoryCache($clock), null, $clock))->combine(Presets::apiRateLimiting()),
        );

        // Far more than any preset limit — none of these are on /api, so none count.
        for ($i = 0; $i < 50; ++$i) {
            $this->assertTrue($firewall->decide($this->request('GET', '/storefront'))->isPass());
        }
    }

    public function testLoginProtectionBansAfterRepeatedFailures(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::loginProtection()));
        $attacker = '198.51.100.10';
        $attackerRequest = $this->request('POST', '/login', $attacker);
        $failure = new RecordedSignal(Presets::LOGIN_FAILURE_RULE, BanType::Fail2Ban);

        // threshold = 5 with >= semantics: the 5th recorded failure triggers the
        // ban. Failures arrive only through RequestContext::recordFailure() — here
        // driven directly via the firewall's recorded-signal path.
        for ($i = 1; $i <= 4; ++$i) {
            $firewall->processRecordedSignal($failure, $attackerRequest);
            $this->assertTrue($firewall->decide($attackerRequest)->isPass());
        }

        $firewall->processRecordedSignal($failure, $attackerRequest);

        // A subsequent request from the banned IP is blocked by fail2ban.
        $blocked = $firewall->decide($attackerRequest);
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
        $this->assertSame('fail2ban', $blocked->blockType);
        $this->assertSame(Presets::LOGIN_FAILURE_RULE, $blocked->rule);

        // A different IP is unaffected.
        $this->assertTrue($firewall->decide($this->request('POST', '/login', '203.0.113.99'))->isPass());
    }

    public function testLoginProtectionIgnoresSpoofableMarkerHeader(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::loginProtection()));

        // The login fail2ban uses a never-match filter, so forging the legacy
        // marker header can never drive a ban. Were it still honoured, the 5th
        // request would be banned; all stay below the /login throttle ceiling.
        $spoofed = $this->request('POST', '/login', '198.51.100.66')
            ->withHeader('X-Phirewall-Login-Failed', '1');
        for ($i = 1; $i <= 8; ++$i) {
            $this->assertTrue(
                $firewall->decide($spoofed)->isPass(),
                'A spoofable marker header must never trip the login fail2ban',
            );
        }
    }

    public function testLoginProtectionBansViaRecordedSignalThroughMiddleware(): void
    {
        $config = (new Config(new InMemoryCache()))->combine(Presets::loginProtection());
        $middleware = new Middleware($config, new Psr17Factory());

        $handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    // Login handler reports a failed authentication; no marker header needed.
                    $context->recordFailure(Presets::LOGIN_FAILURE_RULE);
                }

                return new Response(401);
            }
        };

        $attacker = ['REMOTE_ADDR' => '198.51.100.77'];

        // Five recorded failures reach the threshold; the ban is applied post-handler.
        for ($i = 1; $i <= 5; ++$i) {
            $response = $middleware->process(new ServerRequest('POST', '/login', [], null, '1.1', $attacker), $handler);
            $this->assertSame(401, $response->getStatusCode(), sprintf('Attempt %d still reaches the handler', $i));
        }

        // The next request is blocked by the firewall before the handler runs.
        $blocked = $middleware->process(new ServerRequest('POST', '/login', [], null, '1.1', $attacker), $handler);
        $this->assertSame(403, $blocked->getStatusCode());
    }

    public function testLoginProtectionThrottlesLoginPath(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->combine(Presets::loginProtection()));

        // 10 attempts/minute on /login (no failure marker, so fail2ban stays out of it).
        for ($i = 1; $i <= 10; ++$i) {
            $this->assertTrue($firewall->decide($this->request('POST', '/login', '203.0.113.5'))->isPass());
        }

        $throttled = false;
        for ($i = 11; $i <= 15; ++$i) {
            if ($firewall->decide($this->request('POST', '/login', '203.0.113.5'))->outcome === Outcome::THROTTLED) {
                $throttled = true;
                break;
            }
        }

        $this->assertTrue($throttled, 'Login attempts beyond the limit must be throttled');
    }

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
        // slashes — the exact evasions a PATH_EXACT match would have let through.
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
        $this->assertNotSame(Presets::apiRateLimiting(), Presets::apiRateLimiting());

        $cache = new InMemoryCache();
        $configA = (new Config($cache))->combine(Presets::scannerBlocking());
        $configB = (new Config($cache))->combine(Presets::scannerBlocking());
        $this->assertNotSame($configA, $configB);
        $this->assertNotSame($configA->blocklists, $configB->blocklists);
    }

    public function testPortableAccessorsExposeNamespacedRules(): void
    {
        $this->assertSame(
            ['preset.api.burst', 'preset.api.sustained'],
            array_column(Presets::apiRateLimiting()->toArray()['throttles'], 'name'),
        );

        $this->assertSame(
            ['preset.scanner.known-tools', 'preset.scanner.suspicious-headers'],
            array_column(Presets::scannerBlocking()->toArray()['blocklists'], 'name'),
        );

        $this->assertSame(
            [Presets::LOGIN_FAILURE_RULE],
            array_column(Presets::loginProtection()->toArray()['fail2bans'], 'name'),
        );
    }

    public function testPresetPortableRoundTripsAsSignedTransport(): void
    {
        $secretKey = random_bytes(32);
        $portable = Presets::apiRateLimiting();

        $restored = PortableConfig::loadSigned($portable->toSignedJson($secretKey), $secretKey);
        $this->assertSame($portable->toArray(), $restored->toArray());
    }

    public function testVersionAndNamesAreExposed(): void
    {
        $this->assertSame('1.0.0', Presets::VERSION);
        $this->assertSame(Presets::VERSION, Presets::version());
        $this->assertSame(
            [
                Presets::API_RATE_LIMITING,
                Presets::LOGIN_PROTECTION,
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

        $stricter = new Config($cache);
        $stricter->fail2ban->add(
            name: Presets::LOGIN_FAILURE_RULE,
            threshold: 2,
            period: 600,
            ban: 600,
            filter: static fn(): bool => false,
            key: KeyExtractors::ip(),
        );

        $effective = (new Config($cache))->combine(Presets::loginProtection())->mergedWith($stricter);
        $this->assertSame([Presets::LOGIN_FAILURE_RULE], array_keys($effective->fail2ban->rules()));

        $firewall = new Firewall($effective);
        $attacker = '198.51.100.30';
        $attackerRequest = $this->request('POST', '/login', $attacker);
        $failure = new RecordedSignal(Presets::LOGIN_FAILURE_RULE, BanType::Fail2Ban);

        // Overridden threshold = 2: banned on the 2nd recorded failure, not the 5th.
        $firewall->processRecordedSignal($failure, $attackerRequest);
        $this->assertTrue($firewall->decide($attackerRequest)->isPass());

        $firewall->processRecordedSignal($failure, $attackerRequest);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($attackerRequest)->outcome);
    }

    private function request(string $method, string $path, string $ip = '203.0.113.1'): ServerRequest
    {
        return new ServerRequest($method, $path, [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function apiRequest(string $ip = '203.0.113.1'): ServerRequest
    {
        return $this->request('GET', '/api/users', $ip);
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
