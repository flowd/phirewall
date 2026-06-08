<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class ConfigTypedApiTest extends TestCase
{
    public function testAddAndGetRulesByName(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->addRule(new SafelistRule('s', new ClosureRequestMatcher(static fn($r): bool => true)));
        $config->blocklists->addRule(new BlocklistRule('b', new ClosureRequestMatcher(static fn($r): bool => false)));
        $config->throttles->addRule(new ThrottleRule('t', 10, 60, new ClosureKeyExtractor(static fn($r): string => 'k')));
        $config->fail2ban->addRule(new Fail2BanRule('f', 3, 120, 600, new ClosureRequestMatcher(static fn($r): bool => true), new ClosureKeyExtractor(static fn($r): string => 'ip')));
        $config->tracks->addRule(new TrackRule('tr', 30, new ClosureRequestMatcher(static fn($r): bool => true), new ClosureKeyExtractor(static fn($r): string => 'ua')));

        $this->assertArrayHasKey('s', $config->safelists->rules());
        $this->assertArrayHasKey('b', $config->blocklists->rules());
        $this->assertArrayHasKey('t', $config->throttles->rules());
        $this->assertArrayHasKey('f', $config->fail2ban->rules());
        $this->assertArrayHasKey('tr', $config->tracks->rules());
    }

    public function testResponseFactorySettersAndGetters(): void
    {
        $config = new Config(new InMemoryCache());
        $blockFactory = new ClosureBlocklistedResponseFactory(static fn(string $r, string $t, $req): Response => new Response(418));
        $throttleFactory = new ClosureThrottledResponseFactory(static fn(string $r, int $ra, $req): Response => new Response(420));
        $config->blocklistedResponseFactory = $blockFactory;
        $config->throttledResponseFactory = $throttleFactory;
        $this->assertSame($blockFactory, $config->blocklistedResponseFactory);
        $this->assertSame($throttleFactory, $config->throttledResponseFactory);
    }

    public function testEnableRateLimitHeadersFlag(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertFalse($config->rateLimitHeadersEnabled());
        $config->enableRateLimitHeaders();
        $this->assertTrue($config->rateLimitHeadersEnabled());
        $config->enableRateLimitHeaders(false);
        $this->assertFalse($config->rateLimitHeadersEnabled());
    }

    public function testConfigNowUsesClockWhenProvided(): void
    {
        $fakeClock = new \Flowd\Phirewall\Tests\Support\FakeClock(1_200_000_000.0);
        $config = new Config(new InMemoryCache($fakeClock), clock: $fakeClock);

        $this->assertEqualsWithDelta(1_200_000_000.0, $config->now(), PHP_FLOAT_EPSILON);

        $fakeClock->advance(42.5);
        $this->assertEqualsWithDelta(1_200_000_042.5, $config->now(), PHP_FLOAT_EPSILON);
    }

    public function testConfigNowFallsBackToMicrotimeWithoutClock(): void
    {
        $config = new Config(new InMemoryCache());
        $now = $config->now();
        $this->assertGreaterThan(0.0, $now);
        $this->assertEqualsWithDelta(microtime(true), $now, 1.0);
    }

    public function testIsEnabledByDefault(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertTrue($config->isEnabled());
    }

    public function testDiscriminatorNormalizerDefaultsToNull(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertNull($config->getDiscriminatorNormalizer());
    }

    public function testSetKeyPrefixNormalizationAndValidation(): void
    {
        $config = new Config(new InMemoryCache());

        // Surrounding whitespace is trimmed and trailing colons are stripped,
        // so a prefix written as a namespace separator still works.
        $config->setKeyPrefix('  app.prod:  ');
        $this->assertSame('app.prod', $config->getKeyPrefix());

        $this->expectException(\InvalidArgumentException::class);
        $config->setKeyPrefix('   ');
    }

    public function testSetKeyPrefixRejectsInternalReservedCharacter(): void
    {
        $config = new Config(new InMemoryCache());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('reserved character ":"');
        $config->setKeyPrefix('my:app');
    }

    public function testSetKeyPrefixRejectsControlOrWhitespaceCharacter(): void
    {
        $config = new Config(new InMemoryCache());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('control or whitespace character');
        $config->setKeyPrefix("my\tapp");
    }

    public function testSetKeyPrefixAcceptsValidPrefixAndIsUsable(): void
    {
        $config = new Config(new InMemoryCache());
        $config->setKeyPrefix('my.app');

        $this->assertSame('my.app', $config->getKeyPrefix());
        // A valid prefix must produce a key the cache backends accept.
        $config->cache->set($config->cacheKeyGenerator()->throttleKey('login', '203.0.113.1'), 1);
        $this->assertTrue($config->cache->has($config->cacheKeyGenerator()->throttleKey('login', '203.0.113.1')));
    }

    public function testDiagnosticsCountersLifecycle(): void
    {
        $diagnosticsCounters = new Config\DiagnosticsCounters();
        $this->assertSame([], $diagnosticsCounters->all());

        $diagnosticsCounters->increment('throttle_exceeded');
        $diagnosticsCounters->increment('throttle_exceeded', 't1');
        $diagnosticsCounters->increment('throttle_exceeded', 't1');
        $diagnosticsCounters->increment('blocklisted', 'b1');

        $snapshot = $diagnosticsCounters->all();
        $this->assertArrayHasKey('throttle_exceeded', $snapshot);
        $this->assertSame(3, $snapshot['throttle_exceeded']['total']);
        $this->assertSame(2, $snapshot['throttle_exceeded']['by_rule']['t1']);
        $this->assertSame(1, $snapshot['blocklisted']['total']);
        $this->assertSame(1, $snapshot['blocklisted']['by_rule']['b1']);

        $diagnosticsCounters->reset();
        $this->assertSame([], $diagnosticsCounters->all());
    }

    public function testDiagnosticsCountersCapPerRuleEntries(): void
    {
        $diagnosticsCounters = new Config\DiagnosticsCounters();

        for ($i = 0; $i < 150; ++$i) {
            $diagnosticsCounters->increment('throttle_exceeded', 'rule-' . $i);
        }

        $counters = $diagnosticsCounters->all();
        $this->assertSame(150, $counters['throttle_exceeded']['total'] ?? 0);
        $this->assertLessThanOrEqual(100, count($counters['throttle_exceeded']['by_rule'] ?? []));
    }
}
