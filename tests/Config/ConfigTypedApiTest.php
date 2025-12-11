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
        $config->addSafelist(new SafelistRule('s', new ClosureRequestMatcher(static fn($r): bool => true)));
        $config->addBlocklist(new BlocklistRule('b', new ClosureRequestMatcher(static fn($r): bool => false)));
        $config->addThrottle(new ThrottleRule('t', 10, 60, new ClosureKeyExtractor(static fn($r): string => 'k')));
        $config->addFail2Ban(new Fail2BanRule('f', 3, 120, 600, new ClosureRequestMatcher(static fn($r): bool => true), new ClosureKeyExtractor(static fn($r): string => 'ip')));
        $config->addTrack(new TrackRule('tr', 30, new ClosureRequestMatcher(static fn($r): bool => true), new ClosureKeyExtractor(static fn($r): string => 'ua')));

        $this->assertArrayHasKey('s', $config->getSafelistRules());
        $this->assertArrayHasKey('b', $config->getBlocklistRules());
        $this->assertArrayHasKey('t', $config->getThrottleRules());
        $this->assertArrayHasKey('f', $config->getFail2BanRules());
        $this->assertArrayHasKey('tr', $config->getTrackRules());
    }

    public function testResponseFactorySettersAndGetters(): void
    {
        $config = new Config(new InMemoryCache());
        $blockFactory = new ClosureBlocklistedResponseFactory(static fn(string $r, string $t, $req): \Nyholm\Psr7\Response => new Response(418));
        $throttleFactory = new ClosureThrottledResponseFactory(static fn(string $r, int $ra, $req): \Nyholm\Psr7\Response => new Response(420));
        $config->setBlocklistedResponseFactory($blockFactory);
        $config->setThrottledResponseFactory($throttleFactory);
        $this->assertSame($blockFactory, $config->getBlocklistedResponseFactory());
        $this->assertSame($throttleFactory, $config->getThrottledResponseFactory());
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

    public function testSetKeyPrefixNormalizationAndValidation(): void
    {
        $config = new Config(new InMemoryCache());
        $config->setKeyPrefix('  app:prod:  ');
        $this->assertSame('app:prod', $config->getKeyPrefix());

        $this->expectException(\InvalidArgumentException::class);
        $config->setKeyPrefix('   ');
    }

    public function testDiagnosticsCountersLifecycle(): void
    {
        $config = new Config(new InMemoryCache());
        $config->resetDiagnosticsCounters();
        $this->assertSame([], $config->getDiagnosticsCounters());

        $config->incrementDiagnosticsCounter('throttle_exceeded');
        $config->incrementDiagnosticsCounter('throttle_exceeded', 't1');
        $config->incrementDiagnosticsCounter('throttle_exceeded', 't1');
        $config->incrementDiagnosticsCounter('blocklisted', 'b1');

        $snapshot = $config->getDiagnosticsCounters();
        $this->assertArrayHasKey('throttle_exceeded', $snapshot);
        $this->assertSame(3, $snapshot['throttle_exceeded']['total']);
        $this->assertSame(2, $snapshot['throttle_exceeded']['by_rule']['t1']);
        $this->assertSame(1, $snapshot['blocklisted']['total']);
        $this->assertSame(1, $snapshot['blocklisted']['by_rule']['b1']);

        $config->resetDiagnosticsCounters();
        $this->assertSame([], $config->getDiagnosticsCounters());
    }

    public function testDiagnosticsCountersCapPerRuleEntries(): void
    {
        $config = new Config(new InMemoryCache());

        // Simulate many distinct rules in the same category
        for ($i = 0; $i < 150; ++$i) {
            $config->incrementDiagnosticsCounter('throttle_exceeded', 'rule-' . $i);
        }

        $counters = $config->getDiagnosticsCounters();
        $this->assertSame(150, $counters['throttle_exceeded']['total'] ?? 0);
        // by_rule should be capped at 100 distinct entries
        $this->assertLessThanOrEqual(100, count($counters['throttle_exceeded']['by_rule'] ?? []));
    }
}
