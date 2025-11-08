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
        $this->assertTrue($safelistRule->matcher()->matches(new ServerRequest('GET', '/')));
        $this->assertFalse($safelistRule->matcher()->matches(new ServerRequest('POST', '/')));
    }

    public function testBlocklistRuleStoresNameAndMatcher(): void
    {
        $matcher = new ClosureRequestMatcher(static fn($r): bool => $r->getUri()->getPath() === '/admin');
        $blocklistRule = new BlocklistRule('block', $matcher);
        $this->assertSame('block', $blocklistRule->name());
        $this->assertTrue($blocklistRule->matcher()->matches(new ServerRequest('GET', '/admin')));
        $this->assertFalse($blocklistRule->matcher()->matches(new ServerRequest('GET', '/')));
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

    public function testFail2BanRuleStoresValues(): void
    {
        $filter = new ClosureRequestMatcher(static fn($r): bool => $r->getHeaderLine('X') === '1');
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'ip');
        $fail2BanRule = new Fail2BanRule('f2b', 3, 120, 600, $filter, $extractor);
        $this->assertSame('f2b', $fail2BanRule->name());
        $this->assertSame(3, $fail2BanRule->threshold());
        $this->assertSame(120, $fail2BanRule->period());
        $this->assertSame(600, $fail2BanRule->banSeconds());
        $this->assertTrue($fail2BanRule->filter()->matches((new ServerRequest('GET', '/'))->withHeader('X', '1')));
        $this->assertSame('ip', $fail2BanRule->keyExtractor()->extract(new ServerRequest('GET', '/')));
    }

    public function testTrackRuleStoresValues(): void
    {
        $filter = new ClosureRequestMatcher(static fn($r): bool => true);
        $extractor = new ClosureKeyExtractor(static fn($r): string => 'agent');
        $trackRule = new TrackRule('track', 30, $filter, $extractor);
        $this->assertSame('track', $trackRule->name());
        $this->assertSame(30, $trackRule->period());
        $this->assertTrue($trackRule->filter()->matches(new ServerRequest('GET', '/')));
        $this->assertSame('agent', $trackRule->keyExtractor()->extract(new ServerRequest('GET', '/')));
    }
}
