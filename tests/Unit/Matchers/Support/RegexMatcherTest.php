<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers\Support;

use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use PHPUnit\Framework\TestCase;

final class RegexMatcherTest extends TestCase
{
    public function testCompileValidPattern(): void
    {
        $this->assertSame('/foo/', RegexMatcher::compile('/foo/'));
    }

    public function testCompileInvalidPattern(): void
    {
        $this->assertNull(RegexMatcher::compile('/[invalid/'));
    }

    public function testCompileTooLongPattern(): void
    {
        $pattern = '/' . str_repeat('a', RegexMatcher::MAX_PATTERN_LENGTH + 1) . '/';
        $this->assertNull(RegexMatcher::compile($pattern));
    }

    public function testMatchesValidPattern(): void
    {
        $this->assertTrue(RegexMatcher::matches('/hello/', 'hello world'));
        $this->assertFalse(RegexMatcher::matches('/goodbye/', 'hello world'));
    }

    public function testMatchesNullPatternReturnsFalse(): void
    {
        $this->assertFalse(RegexMatcher::matches(null, 'anything'));
    }

    public function testMatchesTruncatesLongSubject(): void
    {
        $subject = str_repeat('a', RegexMatcher::MAX_SUBJECT_LENGTH + 1000) . 'needle';
        // The needle is beyond the truncation point, so it won't match
        $this->assertFalse(RegexMatcher::matches('/needle/', $subject));
    }

    public function testMatchesCaseInsensitive(): void
    {
        $this->assertTrue(RegexMatcher::matches('/hello/i', 'HELLO WORLD'));
    }

    public function testMatchesMultiline(): void
    {
        $this->assertTrue(RegexMatcher::matches('/^second/m', "first\nsecond\nthird"));
    }
}
