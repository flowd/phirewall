<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ConfigCompositionTest extends TestCase
{
    public function testLaterLayerReplacesRuleWithSameName(): void
    {
        $baseRule = new BlocklistRule('admin', new ClosureRequestMatcher(static fn(): bool => true));
        $overlayRule = new BlocklistRule('admin', new ClosureRequestMatcher(static fn(): bool => false));

        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->addRule($overlayRule);

        $composed = $this->configFor($baseRule)->with($overlay);

        $rules = $composed->blocklists->rules();
        $this->assertCount(1, $rules);
        $this->assertSame($overlayRule, $rules['admin'], 'Later layer must replace the same-named rule.');
    }

    public function testWithReturnsAnIndependentCopyEvenWithNoLayers(): void
    {
        $base = new Config(new InMemoryCache());
        $base->blocklists->add('admin', static fn(): bool => true);

        $copy = $base->with();

        $this->assertNotSame($base, $copy, 'with() must always return a new Config, never the receiver.');
        $this->assertSame(['admin'], array_keys($copy->blocklists->rules()));

        // A Config is mutable, so the copy must not share rule state with the base.
        $copy->blocklists->add('extra', static fn(): bool => true);
        $this->assertSame(['admin'], array_keys($base->blocklists->rules()));
    }

    public function testEachSectionMergesByName(): void
    {
        $base = new Config(new InMemoryCache());
        $base->safelists->add('health', static fn(): bool => true);
        $base->blocklists->add('admin', static fn(): bool => true);
        $base->throttles->add('api', 10, 60, static fn(): string => 'k');
        $base->fail2ban->add('login', 5, 60, 900, static fn(): bool => true, static fn(): string => 'k');
        $base->allow2ban->add('cap', 100, 60, 300, static fn(): string => 'k');
        $base->tracks->add('audit', 60, static fn(): bool => true, static fn(): string => 'k');

        $overlay = new Config(new InMemoryCache());
        // Same names — must replace; plus a brand-new name per section — must append.
        $overlay->safelists->add('health', static fn(): bool => false);
        $overlay->safelists->add('office', static fn(): bool => true);

        $overlay->blocklists->add('admin', static fn(): bool => false);
        $overlay->blocklists->add('wp', static fn(): bool => true);

        $overlay->throttles->add('api', 20, 60, static fn(): string => 'k');
        $overlay->throttles->add('search', 5, 60, static fn(): string => 'k');

        $overlay->fail2ban->add('login', 3, 60, 600, static fn(): bool => true, static fn(): string => 'k');
        $overlay->fail2ban->add('signup', 3, 60, 600, static fn(): bool => true, static fn(): string => 'k');

        $overlay->allow2ban->add('cap', 50, 60, 300, static fn(): string => 'k');
        $overlay->allow2ban->add('burst', 10, 1, 60, static fn(): string => 'k');

        $overlay->tracks->add('audit', 120, static fn(): bool => true, static fn(): string => 'k');
        $overlay->tracks->add('metrics', 60, static fn(): bool => true, static fn(): string => 'k');

        $composed = $base->with($overlay);

        // Union by name: 1 overridden + 1 new = 2 per section.
        $this->assertSame(['health', 'office'], array_keys($composed->safelists->rules()));
        $this->assertSame(['admin', 'wp'], array_keys($composed->blocklists->rules()));
        $this->assertSame(['api', 'search'], array_keys($composed->throttles->rules()));
        $this->assertSame(['login', 'signup'], array_keys($composed->fail2ban->rules()));
        $this->assertSame(['cap', 'burst'], array_keys($composed->allow2ban->rules()));
        $this->assertSame(['audit', 'metrics'], array_keys($composed->tracks->rules()));

        // The overridden entries carry the overlay's values.
        $this->assertSame(20, $composed->throttles->rules()['api']->resolveLimit(new ServerRequest('GET', '/')));
        $this->assertSame(3, $composed->fail2ban->rules()['login']->threshold());
        $this->assertSame(50, $composed->allow2ban->rules()['cap']->threshold());
        $this->assertSame(120, $composed->tracks->rules()['audit']->period());
    }

    public function testBaseOrderingIsPreservedAndNewRulesAppended(): void
    {
        $base = new Config(new InMemoryCache());
        $base->blocklists->add('first', static fn(): bool => true);
        $base->blocklists->add('second', static fn(): bool => true);
        $base->blocklists->add('third', static fn(): bool => true);

        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->add('second', static fn(): bool => false); // replace in place
        $overlay->blocklists->add('fourth', static fn(): bool => true);  // append

        $composed = $base->with($overlay);

        $this->assertSame(['first', 'second', 'third', 'fourth'], array_keys($composed->blocklists->rules()));
    }

    public function testScalarOptionsTakeLastExplicitValue(): void
    {
        $resolverA = static fn(ServerRequestInterface $serverRequest): string => 'A';
        $resolverB = static fn(ServerRequestInterface $serverRequest): string => 'B';
        $normalizerA = static fn(string $value): string => $value . '-a';
        $normalizerB = static fn(string $value): string => $value . '-b';
        $blockFactory = $this->blocklistedResponseFactory();
        $throttleFactory = $this->throttledResponseFactory();

        $base = (new Config(new InMemoryCache()))
            ->setKeyPrefix('base')
            ->setFailOpen(false)
            ->enableResponseHeaders(true)
            ->enableRateLimitHeaders(true)
            ->setIpResolver($resolverA)
            ->setDiscriminatorNormalizer($normalizerA);
        $base->blocklistedResponseFactory = $blockFactory;

        $overlay = (new Config(new InMemoryCache()))
            ->setKeyPrefix('tenant')
            ->enableOwaspDiagnosticsHeader(true)
            ->setIpResolver($resolverB)
            ->setDiscriminatorNormalizer($normalizerB);
        $overlay->throttledResponseFactory = $throttleFactory;

        $composed = $base->with($overlay);

        $this->assertSame('tenant', $composed->getKeyPrefix());        // last explicit string
        $this->assertFalse($composed->isFailOpen());                   // only base set it (non-default)
        $this->assertTrue($composed->responseHeadersEnabled());        // only base set it
        $this->assertTrue($composed->rateLimitHeadersEnabled());       // only base set it
        $this->assertTrue($composed->owaspDiagnosticsHeaderEnabled()); // only overlay set it
        $this->assertSame($resolverB, $composed->getIpResolver());
        $this->assertSame($normalizerB, $composed->getDiscriminatorNormalizer());
        $this->assertSame($blockFactory, $composed->blocklistedResponseFactory);   // inherited from base
        $this->assertSame($throttleFactory, $composed->throttledResponseFactory);  // inherited from overlay
    }

    public function testIpRuleWithoutExplicitResolverUsesComposedResolver(): void
    {
        // Base config: an IP blocklist added WITHOUT an explicit resolver.
        $base = new Config(new InMemoryCache());
        $base->blocklists->ip('bad-net', '203.0.113.7');

        // Overlay config: sets a header-based IP resolver (e.g. behind a proxy).
        $overlay = new Config(new InMemoryCache());
        $overlay->setIpResolver(static function (ServerRequestInterface $serverRequest): ?string {
            $value = $serverRequest->getHeaderLine('X-Real-IP');
            return $value === '' ? null : $value;
        });

        // Composed config inherits the overlay's resolver; the carried-over IP rule
        // late-binds to it, so the banned client arriving via X-Real-IP is blocked
        // even though REMOTE_ADDR is harmless.
        $firewall = new Firewall($base->with($overlay));

        $blocked = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $clean = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '198.51.100.9');

        $this->assertSame(Outcome::BLOCKED, $firewall->decide($blocked)->outcome);
        $this->assertTrue($firewall->decide($clean)->isPass());
    }

    public function testDefaultValuesDoNotClobberEarlierExplicitValues(): void
    {
        // base makes explicit, non-default choices; overlay leaves everything default.
        $base = (new Config(new InMemoryCache()))
            ->setKeyPrefix('base')
            ->setFailOpen(false)
            ->disable();

        $overlay = new Config(new InMemoryCache()); // all defaults

        $composed = $base->with($overlay);

        $this->assertSame('base', $composed->getKeyPrefix());
        $this->assertFalse($composed->isFailOpen());
        // `enabled` is the deliberate exception: it uses last-layer-wins (fail-safe),
        // so the overlay (highest priority) re-enables rather than inheriting the
        // base's disable(). The firewall must not stay silently off.
        $this->assertTrue($composed->isEnabled());
    }

    public function testEnabledUsesLastLayerWinsFailSafe(): void
    {
        // An explicit re-enable on the winning layer must override an earlier disable.
        $base = (new Config(new InMemoryCache()))->disable();
        $overlay = (new Config(new InMemoryCache()))->enable();
        $this->assertTrue($base->with($overlay)->isEnabled());

        // The highest-priority layer's explicit disable still wins.
        $enabledBase = new Config(new InMemoryCache());
        $disablingOverlay = (new Config(new InMemoryCache()))->disable();
        $this->assertFalse($enabledBase->with($disablingOverlay)->isEnabled());
    }

    public function testInputsAreNotMutatedByComposition(): void
    {
        $base = (new Config(new InMemoryCache()))->setKeyPrefix('base');
        $base->blocklists->add('admin', static fn(): bool => true);
        $base->blocklists->patternBlocklist('threats', [new PatternEntry(PatternKind::PATH_EXACT, '/.env')]);

        $overlay = (new Config(new InMemoryCache()))->setKeyPrefix('tenant')->setFailOpen(false);
        $overlay->blocklists->add('admin', static fn(): bool => false);
        $overlay->blocklists->add('wp', static fn(): bool => true);

        $baseBlocklistCount = count($base->blocklists->rules());
        $baseBackendCount = count($base->blocklists->patternBackends());
        $overlayBlocklistCount = count($overlay->blocklists->rules());

        $base->with($overlay);

        $this->assertCount($baseBlocklistCount, $base->blocklists->rules());
        $this->assertCount($baseBackendCount, $base->blocklists->patternBackends());
        $this->assertCount($overlayBlocklistCount, $overlay->blocklists->rules());
        $this->assertSame('base', $base->getKeyPrefix());
        $this->assertTrue($base->isFailOpen());
        $this->assertSame('tenant', $overlay->getKeyPrefix());
        $this->assertFalse($overlay->isFailOpen());
    }

    public function testComposedConfigInheritsBaseInfrastructure(): void
    {
        $cache = new InMemoryCache();
        $dispatcher = $this->eventDispatcher();
        $clock = new FakeClock(1_234.5);
        $base = new Config($cache, $dispatcher, $clock);

        $overlayCache = new InMemoryCache();
        $overlay = new Config($overlayCache, $this->eventDispatcher(), new FakeClock(9_999.0));

        $composed = $base->with($overlay);

        $this->assertSame($cache, $composed->cache, 'Composed Config uses the base cache.');
        $this->assertSame($dispatcher, $composed->eventDispatcher, 'Composed Config uses the base dispatcher.');
        $this->assertEqualsWithDelta(1_234.5, $composed->now(), PHP_FLOAT_EPSILON);
    }

    public function testMergedWithIsEquivalentToCompose(): void
    {
        $base = new Config(new InMemoryCache());
        $base->blocklists->add('admin', static fn(): bool => true);

        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->add('wp', static fn(): bool => true);

        $composed = $base->with($overlay);

        $this->assertSame(['admin', 'wp'], array_keys($composed->blocklists->rules()));
        $this->assertNotSame($base, $composed);
        $this->assertNotSame($overlay, $composed);
    }

    public function testWithReturnsANewConfigAndLeavesTheBaseUntouched(): void
    {
        $base = (new Config(new InMemoryCache()))->setKeyPrefix('base');
        $base->blocklists->add('admin', static fn(): bool => true);

        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->add('wp', static fn(): bool => true);

        $composed = $base->with($overlay);

        $this->assertNotSame($base, $composed);
        $this->assertSame(['admin', 'wp'], array_keys($composed->blocklists->rules()));
        // The base is unchanged by the composition.
        $this->assertSame(['admin'], array_keys($base->blocklists->rules()));
        $this->assertSame('base', $composed->getKeyPrefix());
    }

    public function testPatternBackendsAreMergedByName(): void
    {
        $base = new Config(new InMemoryCache());
        $base->blocklists->addPatternBackend('threats', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::PATH_EXACT, '/.env'),
        ]));

        $overlayBackend = new InMemoryPatternBackend([new PatternEntry(PatternKind::PATH_EXACT, '/.git')]);
        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->addPatternBackend('threats', $overlayBackend); // override by name
        $overlay->blocklists->addPatternBackend('extra', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::PATH_EXACT, '/wp-login.php'),
        ]));

        $composed = $base->with($overlay);

        $backends = $composed->blocklists->patternBackends();
        $this->assertSame(['threats', 'extra'], array_keys($backends));
        $this->assertSame($overlayBackend, $backends['threats']);
    }

    public function testComposeRepointsRulesToOverriddenPatternBackend(): void
    {
        // Base registers backend "threats" AND a rule that consults it.
        $base = new Config(new InMemoryCache());
        $base->blocklists->addPatternBackend('threats', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::PATH_EXACT, '/old-threat'),
        ]));
        $base->blocklists->fromBackend('threats-rule', 'threats');

        // A later layer overrides the "threats" backend by name (different
        // contents) without redefining the rule.
        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->addPatternBackend('threats', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::PATH_EXACT, '/new-threat'),
        ]));

        $firewall = new Firewall($base->with($overlay));

        // The override now reaches the carried-over rule: the overlay's threat is
        // blocked, and the replaced backend's entry no longer matches.
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('GET', '/new-threat'))->outcome);
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/old-threat'))->isPass());
    }

    public function testRepointedPatternRuleStillLateBindsComposedResolver(): void
    {
        // Base: a pattern blocklist (IP entry) with no explicit resolver.
        $base = new Config(new InMemoryCache());
        $base->blocklists->addPatternBackend('feed', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::IP, '203.0.113.7'),
        ]));
        $base->blocklists->fromBackend('feed-rule', 'feed');

        // Overlay overrides the "feed" backend by name AND sets a header IP resolver.
        $overlay = new Config(new InMemoryCache());
        $overlay->blocklists->addPatternBackend('feed', new InMemoryPatternBackend([
            new PatternEntry(PatternKind::IP, '203.0.113.7'),
        ]));
        $overlay->setIpResolver(static function (ServerRequestInterface $serverRequest): ?string {
            $value = $serverRequest->getHeaderLine('X-Real-IP');
            return $value === '' ? null : $value;
        });

        // The rule is re-pointed to the overlay backend (withBackend) AND must still
        // late-bind to the composed resolver, so the banned client arriving via
        // X-Real-IP is blocked despite a harmless REMOTE_ADDR.
        $firewall = new Firewall($base->with($overlay));

        $viaHeader = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($viaHeader)->outcome);

        $viaRemoteAddr = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']);
        $this->assertTrue($firewall->decide($viaRemoteAddr)->isPass());
    }

    public function testTypedRulesAreCarriedAcrossEverySection(): void
    {
        $base = new Config(new InMemoryCache());
        $base->safelists->addRule(new SafelistRule('s', new ClosureRequestMatcher(static fn(): bool => false)));
        $base->throttles->addRule(new ThrottleRule('t', 1, 60, new ClosureKeyExtractor(KeyExtractors::ip())));
        $base->fail2ban->addRule(new Fail2BanRule('f', 1, 60, 60, new ClosureRequestMatcher(static fn(): bool => false), new ClosureKeyExtractor(KeyExtractors::ip())));
        $base->allow2ban->addRule(new Allow2BanRule('a', 1, 60, 60, new ClosureKeyExtractor(KeyExtractors::ip())));
        $base->tracks->addRule(new TrackRule('tr', 60, new ClosureRequestMatcher(static fn(): bool => false), new ClosureKeyExtractor(KeyExtractors::ip())));

        $composed = $base->with(new Config(new InMemoryCache()));

        $this->assertCount(1, $composed->safelists->rules());
        $this->assertCount(1, $composed->throttles->rules());
        $this->assertCount(1, $composed->fail2ban->rules());
        $this->assertCount(1, $composed->allow2ban->rules());
        $this->assertCount(1, $composed->tracks->rules());
    }

    public function testLayeringPortableConfigsEndToEnd(): void
    {
        $cache = new InMemoryCache();

        // A vendor baseline shipped as portable data.
        $baseline = PortableConfig::create()
            ->setKeyPrefix('vendor')
            ->safelist('health', PortableConfig::filterPathEquals('/health'))
            ->blocklist('scanners', PortableConfig::filterKnownScanners()); // default list incl. sqlmap

        // A tenant overlay, also portable: it OVERRIDES "scanners" (now only "evilbot")
        // and adds a NEW "admin" blocklist, while flipping the key prefix + fail-closed.
        $overlay = PortableConfig::create()
            ->setKeyPrefix('tenant')
            ->setFailOpen(false)
            ->blocklist('scanners', PortableConfig::filterKnownScanners(['evilbot']))
            ->blocklist('admin', PortableConfig::filterPathPrefix('/admin'));

        $composed = (new Config($cache))->with($baseline, $overlay);

        // Unioned rule sets across layers.
        $this->assertSame(['health'], array_keys($composed->safelists->rules()));
        $this->assertSame(['scanners', 'admin'], array_keys($composed->blocklists->rules()));

        // Last-wins option.
        $this->assertSame('tenant', $composed->getKeyPrefix());
        $this->assertFalse($composed->isFailOpen());

        $firewall = new Firewall($composed);

        // Safelist from the baseline still applies.
        $this->assertSame(Outcome::SAFELISTED, $firewall->decide(new ServerRequest('GET', '/health'))->outcome);

        // "scanners" was overridden by name: the default sqlmap UA now passes, evilbot is blocked.
        $this->assertTrue($firewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'))->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'evilbot/1'))->outcome);

        // The brand-new tenant rule blocks /admin.
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('GET', '/admin/users'))->outcome);
    }

    public function testCombinePreservesReceiverEnabledState(): void
    {
        $portable = PortableConfig::create()->blocklist('x', PortableConfig::filterPathEquals('/x'));

        // Combining onto a disabled receiver must NOT silently re-enable it: a
        // PortableConfig cannot express `enabled`, so the materialized layer
        // inherits the receiver's state instead of the default-enabled value.
        $this->assertFalse((new Config(new InMemoryCache()))->disable()->with($portable)->isEnabled());

        // An enabled receiver stays enabled.
        $this->assertTrue((new Config(new InMemoryCache()))->with($portable)->isEnabled());
    }

    private function configFor(BlocklistRule $blocklistRule): Config
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->addRule($blocklistRule);

        return $config;
    }

    private function blocklistedResponseFactory(): BlocklistedResponseFactoryInterface
    {
        return new class () implements BlocklistedResponseFactoryInterface {
            public function create(string $rule, string $type, ServerRequestInterface $serverRequest): ResponseInterface
            {
                throw new \LogicException('not invoked in this test');
            }
        };
    }

    private function throttledResponseFactory(): ThrottledResponseFactoryInterface
    {
        return new class () implements ThrottledResponseFactoryInterface {
            public function create(string $rule, int $retryAfter, ServerRequestInterface $serverRequest): ResponseInterface
            {
                throw new \LogicException('not invoked in this test');
            }
        };
    }

    private function eventDispatcher(): EventDispatcherInterface
    {
        return new class () implements EventDispatcherInterface {
            public function dispatch(object $event): object
            {
                return $event;
            }
        };
    }
}
