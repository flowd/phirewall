<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Pattern;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use PHPUnit\Framework\TestCase;

final class PatternEntryTest extends TestCase
{
    public function testRejectsLineBreakInValue(): void
    {
        // A raw newline would be serialised verbatim by the file backend and re-parse as a
        // second, injected entry on read; reject it at the value-object boundary instead.
        $this->expectException(\InvalidArgumentException::class);

        new PatternEntry(kind: PatternKind::PATH_EXACT, value: "/admin\n/evil");
    }

    public function testRejectsLineBreakInTarget(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new PatternEntry(kind: PatternKind::HEADER_EXACT, value: 'bad', target: "X-Test\r\nInjected");
    }

    public function testAcceptsValuesWithoutLineBreaks(): void
    {
        $entry = new PatternEntry(kind: PatternKind::HEADER_EXACT, value: 'curl/7.0', target: 'User-Agent');

        $this->assertSame('curl/7.0', $entry->value);
        $this->assertSame('User-Agent', $entry->target);
    }
}
