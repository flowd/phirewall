<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\CacheKeyRules;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CacheKeyRules::class)]
final class CacheKeyRulesTest extends TestCase
{
    public function testCleanValueHasNoIllegalCharacter(): void
    {
        $this->assertNull(CacheKeyRules::firstIllegalCharacter('phirewall.throttle.ip-1.2.3.4'));
    }

    public function testReservedCharacterIsReportedAsReserved(): void
    {
        $this->assertSame(['character' => ':', 'reserved' => true], CacheKeyRules::firstIllegalCharacter('a:b'));
        $this->assertSame(['character' => '{', 'reserved' => true], CacheKeyRules::firstIllegalCharacter('a{b'));
    }

    public function testControlOrWhitespaceCharacterIsReportedAsNotReserved(): void
    {
        $this->assertSame(['character' => "\n", 'reserved' => false], CacheKeyRules::firstIllegalCharacter("a\nb"));
        $this->assertSame(['character' => ' ', 'reserved' => false], CacheKeyRules::firstIllegalCharacter('a b'));
    }

    public function testDescribeViolationKeepsReservedCharacterVerbatim(): void
    {
        $message = CacheKeyRules::describeViolation('Cache key', ['character' => ':', 'reserved' => true]);

        $this->assertStringContainsString('reserved character ":"', $message);
    }

    public function testDescribeViolationEscapesControlCharactersForLogSafety(): void
    {
        $message = CacheKeyRules::describeViolation('Cache key', ['character' => "\n", 'reserved' => false]);

        $this->assertStringContainsString('(\x0a)', $message);
        $this->assertStringNotContainsString("\n", $message);
    }
}
