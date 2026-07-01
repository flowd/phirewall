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

    public function testMatchesFailClosedNullPatternReturnsFalse(): void
    {
        $this->assertFalse(RegexMatcher::matchesFailClosed(null, 'anything'));
    }

    public function testMatchesFailClosedNormalMatchAndNonMatch(): void
    {
        $this->assertTrue(RegexMatcher::matchesFailClosed('/hello/', 'hello world'));
        $this->assertFalse(RegexMatcher::matchesFailClosed('/goodbye/', 'hello world'));
    }

    public function testMatchesFailClosedTruncatesLongSubject(): void
    {
        $subject = str_repeat('a', RegexMatcher::MAX_SUBJECT_LENGTH + 1000) . 'needle';
        // The needle is beyond the truncation point, so it won't match.
        $this->assertFalse(RegexMatcher::matchesFailClosed('/needle/', $subject));
    }

    /**
     * A PCRE engine error at match time (here the backtrack limit exceeded on a
     * compile-valid pattern) must count as a match for blocklist callers, while
     * the plain matches() helper still reports no match.
     */
    public function testMatchesFailClosedTreatsEngineErrorAsMatch(): void
    {
        $originalBacktrackLimit = ini_get('pcre.backtrack_limit');
        $originalJit = ini_get('pcre.jit');
        ini_set('pcre.backtrack_limit', '10');
        // Disable JIT so the interpreter honours the lowered backtrack limit.
        ini_set('pcre.jit', '0');

        try {
            $pattern = '/(?:a+)+$/D';
            $subject = str_repeat('a', 100) . '!';

            // Prove the error path: under these limits preg_match itself errors out.
            $this->assertFalse(@preg_match($pattern, $subject), 'Precondition: the pattern must trigger a PCRE engine error');

            $this->assertFalse(RegexMatcher::matches($pattern, $subject), 'matches() treats an engine error as no match');
            $this->assertTrue(RegexMatcher::matchesFailClosed($pattern, $subject), 'matchesFailClosed() treats an engine error as a match');
        } finally {
            if ($originalBacktrackLimit !== false) {
                ini_set('pcre.backtrack_limit', $originalBacktrackLimit);
            }

            if ($originalJit !== false) {
                ini_set('pcre.jit', $originalJit);
            }
        }
    }
}
