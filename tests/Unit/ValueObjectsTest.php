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

    public function testPatternKindCasesCount(): void
    {
        $cases = PatternKind::cases();
        $this->assertCount(8, $cases);
        $this->assertContains(PatternKind::IP, $cases);
        $this->assertContains(PatternKind::CIDR, $cases);
        $this->assertContains(PatternKind::PATH_EXACT, $cases);
        $this->assertContains(PatternKind::HEADER_REGEX, $cases);
        $this->assertContains(PatternKind::REQUEST_REGEX, $cases);
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

    public function testPatternEntryKeyWithoutTarget(): void
    {
        $patternEntry = new PatternEntry(PatternKind::IP, '1.2.3.4');
        $this->assertSame('ip::1.2.3.4', $patternEntry->key());
    }

    public function testPatternEntryKeyWithTarget(): void
    {
        $patternEntry = new PatternEntry(PatternKind::HEADER_EXACT, 'bad', 'User-Agent');
        $this->assertSame('header_exact:User-Agent:bad', $patternEntry->key());
    }

    public function testPatternEntryMergeKeepsLongerExpiry(): void
    {
        $existing = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 5000);
        $incoming = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 9000);
        $merged = $existing->merge($incoming);
        $this->assertSame(9000, $merged->expiresAt);

        $reversed = $incoming->merge($existing);
        $this->assertSame(9000, $reversed->expiresAt);
    }

    public function testPatternEntryMergeKeepsMostRecentAddedAt(): void
    {
        $existing = new PatternEntry(PatternKind::IP, '1.2.3.4', addedAt: 100);
        $incoming = new PatternEntry(PatternKind::IP, '1.2.3.4', addedAt: 200);
        $this->assertSame(200, $existing->merge($incoming)->addedAt);
    }

    public function testPatternEntryMergeBothExpiriesNull(): void
    {
        $existing = new PatternEntry(PatternKind::IP, '1.2.3.4');
        $incoming = new PatternEntry(PatternKind::IP, '1.2.3.4');
        $this->assertNull($existing->merge($incoming)->expiresAt);
    }

    public function testPatternEntryMergePermanentWithExpiring(): void
    {
        $permanent = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: null);
        $expiring = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 5000);
        $this->assertNull($permanent->merge($expiring)->expiresAt);
    }

    public function testPatternEntryMergeExpiringWithPermanent(): void
    {
        $expiring = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 5000);
        $permanent = new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: null);
        $this->assertNull($expiring->merge($permanent)->expiresAt);
    }

    public function testPatternEntryMergePreservesExistingIdentityAndMetadata(): void
    {
        $existing = new PatternEntry(PatternKind::IP, '1.2.3.4', target: 'X', metadata: ['src' => 'file']);
        $incoming = new PatternEntry(PatternKind::CIDR, '9.9.9.0/24', target: 'Y', metadata: ['src' => 'api']);
        $merged = $existing->merge($incoming);

        $this->assertSame(PatternKind::IP, $merged->kind);
        $this->assertSame('1.2.3.4', $merged->value);
        $this->assertSame('X', $merged->target);
        $this->assertSame(['src' => 'file'], $merged->metadata);
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
