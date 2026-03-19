<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use PHPUnit\Framework\TestCase;

final class ValueObjectsTest extends TestCase
{
    public function testMatchResultMatched(): void
    {
        $matchResult = MatchResult::matched('src', ['k' => 'v']);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('src', $matchResult->source());
        $this->assertSame(['k' => 'v'], $matchResult->metadata());
    }

    public function testMatchResultNoMatch(): void
    {
        $matchResult = MatchResult::noMatch();
        $this->assertFalse($matchResult->isMatch());
        $this->assertSame('', $matchResult->source());
        $this->assertSame([], $matchResult->metadata());
    }

    public function testPatternKindAllCount(): void
    {
        $all = PatternKind::all();
        $this->assertCount(8, $all);
        $this->assertContains('ip', $all);
        $this->assertContains('cidr', $all);
        $this->assertContains('path_exact', $all);
        $this->assertContains('header_regex', $all);
        $this->assertContains('request_regex', $all);
    }

    public function testPatternEntryDefaults(): void
    {
        $patternEntry = new PatternEntry(PatternKind::IP, '1.2.3.4');
        $this->assertNull($patternEntry->target);
        $this->assertNull($patternEntry->expiresAt);
        $this->assertNull($patternEntry->addedAt);
        $this->assertSame([], $patternEntry->metadata);
    }

    public function testPatternEntryFull(): void
    {
        $patternEntry = new PatternEntry(PatternKind::HEADER_EXACT, 'bad', 'User-Agent', 999, 100, ['r' => 'test']);
        $this->assertSame('User-Agent', $patternEntry->target);
        $this->assertSame(999, $patternEntry->expiresAt);
        $this->assertSame(100, $patternEntry->addedAt);
        $this->assertSame(['r' => 'test'], $patternEntry->metadata);
    }

    public function testFirewallResultPass(): void
    {
        $firewallResult = FirewallResult::pass();
        $this->assertTrue($firewallResult->isPass());
        $this->assertFalse($firewallResult->isBlocked());
        $this->assertSame(Outcome::PASS, $firewallResult->outcome);
    }

    public function testFirewallResultBlocked(): void
    {
        $firewallResult = FirewallResult::blocked('rule', 'blocklist', ['X-Phirewall' => 'blocklist']);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertFalse($firewallResult->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
    }

    public function testFirewallResultThrottled(): void
    {
        $firewallResult = FirewallResult::throttled('t', 30, ['Retry-After' => '30']);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertSame(30, $firewallResult->retryAfter);
    }

    public function testOutcomeValues(): void
    {
        $this->assertSame('pass', Outcome::PASS->value);
        $this->assertSame('safelisted', Outcome::SAFELISTED->value);
        $this->assertSame('blocked', Outcome::BLOCKED->value);
        $this->assertSame('throttled', Outcome::THROTTLED->value);
    }
}
