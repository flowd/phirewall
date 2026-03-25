<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RuleValueObjectsTest extends TestCase
{
    public function testSafelistRuleStoresNameAndMatcher(): void
    {
        $matcher = new ClosureRequestMatcher(static fn($r): bool => $r->getMethod() === 'GET');
        $safelistRule = new SafelistRule('safe', $matcher);
        $this->assertSame('safe', $safelistRule->name());
        $this->assertTrue($safelistRule->matcher()->match(new ServerRequest('GET', '/'))->isMatch());
        $this->assertFalse($safelistRule->matcher()->match(new ServerRequest('POST', '/'))->isMatch());
    }

    public function testBlocklistRuleStoresNameAndMatcher(): void
    {
        $matcher = new ClosureRequestMatcher(static fn($r): bool => $r->getUri()->getPath() === '/admin');
        $blocklistRule = new BlocklistRule('block', $matcher);
        $this->assertSame('block', $blocklistRule->name());
        $this->assertTrue($blocklistRule->matcher()->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($blocklistRule->matcher()->match(new ServerRequest('GET', '/'))->isMatch());
    }

    public function testThrottleRuleStoresValues(): void
    {
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'k');
        $throttleRule = new ThrottleRule('t', 5, 60, $extractor);
        $this->assertSame('t', $throttleRule->name());
        $this->assertSame(5, $throttleRule->limit());
        $this->assertSame(60, $throttleRule->period());
        $this->assertSame('k', $throttleRule->keyExtractor()->extract(new ServerRequest('GET', '/')));
    }

    public function testThrottleRuleSlidingFlag(): void
    {
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'k');

        $fixedRule = new ThrottleRule('fixed', 5, 60, $extractor);
        $this->assertFalse($fixedRule->isSliding());

        $slidingRule = new ThrottleRule('sliding', 5, 60, $extractor, sliding: true);
        $this->assertTrue($slidingRule->isSliding());
    }

    public function testThrottleRuleWithClosureLimitAndPeriod(): void
    {
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'k');
        $dynamicLimit = static fn($r): int => $r->getHeaderLine('X-Role') === 'admin' ? 100 : 10;
        $dynamicPeriod = static fn($r): int => 120;
        $throttleRule = new ThrottleRule('dynamic', $dynamicLimit, $dynamicPeriod, $extractor);

        $this->assertSame('dynamic', $throttleRule->name());
        $this->assertInstanceOf(\Closure::class, $throttleRule->limit());
        $this->assertInstanceOf(\Closure::class, $throttleRule->period());

        $adminRequest = (new ServerRequest('GET', '/'))->withHeader('X-Role', 'admin');
        $serverRequest = new ServerRequest('GET', '/');
        $this->assertSame(100, $throttleRule->resolveLimit($adminRequest));
        $this->assertSame(10, $throttleRule->resolveLimit($serverRequest));
        $this->assertSame(120, $throttleRule->resolvePeriod($serverRequest));
    }

    public function testFail2BanRuleStoresValues(): void
    {
        $filter = new ClosureRequestMatcher(static fn($r): bool => $r->getHeaderLine('X') === '1');
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'ip');
        $fail2BanRule = new Fail2BanRule('f2b', 3, 120, 600, $filter, $extractor);
        $this->assertSame('f2b', $fail2BanRule->name());
        $this->assertSame(3, $fail2BanRule->threshold());
        $this->assertSame(120, $fail2BanRule->period());
        $this->assertSame(600, $fail2BanRule->banSeconds());
        $this->assertTrue($fail2BanRule->filter()->match((new ServerRequest('GET', '/'))->withHeader('X', '1'))->isMatch());
        $this->assertSame('ip', $fail2BanRule->keyExtractor()->extract(new ServerRequest('GET', '/')));
    }

    public function testTrackRuleStoresValues(): void
    {
        $filter = new ClosureRequestMatcher(static fn($r): bool => true);
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'agent');
        $trackRule = new TrackRule('track', 30, $filter, $extractor);
        $this->assertSame('track', $trackRule->name());
        $this->assertSame(30, $trackRule->period());
        $this->assertTrue($trackRule->filter()->match(new ServerRequest('GET', '/'))->isMatch());
        $this->assertSame('agent', $trackRule->keyExtractor()->extract(new ServerRequest('GET', '/')));
    }

    // ── TrackRule validation tests ──────────────────────────────────────

    public function testTrackRuleEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TrackRule name must not be empty.');

        new TrackRule(
            '',
            60,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    public function testTrackRuleZeroPeriodThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TrackRule period must be >= 1');

        new TrackRule(
            'bad-period',
            0,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    public function testTrackRuleNegativePeriodThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TrackRule period must be >= 1');

        new TrackRule(
            'bad-period',
            -10,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    // ── ThrottleRule validation tests ───────────────────────────────────

    public function testThrottleRuleEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ThrottleRule name must not be empty.');

        new ThrottleRule(
            '',
            10,
            60,
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    // ── BlocklistRule validation tests ──────────────────────────────────

    public function testBlocklistRuleEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('BlocklistRule name must not be empty.');

        new BlocklistRule(
            '',
            new ClosureRequestMatcher(static fn($r): bool => true),
        );
    }

    // ── SafelistRule validation tests ───────────────────────────────────

    public function testSafelistRuleEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('SafelistRule name must not be empty.');

        new SafelistRule(
            '',
            new ClosureRequestMatcher(static fn($r): bool => true),
        );
    }

    // ── Fail2BanRule validation tests ───────────────────────────────────

    public function testFail2BanRuleEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Fail2BanRule name must not be empty.');

        new Fail2BanRule(
            '',
            3,
            120,
            600,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    public function testFail2BanRuleThresholdBelowOneThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Fail2BanRule threshold must be >= 1');

        new Fail2BanRule(
            'f2b-bad',
            0,
            120,
            600,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    public function testFail2BanRulePeriodBelowOneThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Fail2BanRule period must be >= 1');

        new Fail2BanRule(
            'f2b-bad',
            3,
            0,
            600,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }

    public function testFail2BanRuleBanSecondsBelowOneThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Fail2BanRule banSeconds must be >= 1');

        new Fail2BanRule(
            'f2b-bad',
            3,
            120,
            0,
            new ClosureRequestMatcher(static fn($r): bool => true),
            new ClosureKeyExtractor(static fn($r): string => 'k'),
        );
    }
}
