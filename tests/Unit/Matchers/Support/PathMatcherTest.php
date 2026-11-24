<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers\Support;

use Flowd\Phirewall\Http\PathNormalizer;
use Flowd\Phirewall\Matchers\Support\PathMatcher;
use PHPUnit\Framework\TestCase;

final class PathMatcherTest extends TestCase
{
    public function testCompileLiteralNormalisesTheValue(): void
    {
        $literal = PathMatcher::compileLiteral('/my%20dir//./x');
        $this->assertSame('/my%20dir//./x', $literal->raw);
        $this->assertSame('/my dir/x', $literal->normalized);

        $this->assertSame('', PathMatcher::compileLiteral('')->normalized);
    }

    public function testRestrictiveModeMatchesNormalisedOrRaw(): void
    {
        $this->assertTrue(PathMatcher::equals(PathNormalizer::analyze('/%61dmin'), PathMatcher::compileLiteral('/admin'), false));
        $this->assertTrue(PathMatcher::equals(PathNormalizer::analyze('/a/../admin'), PathMatcher::compileLiteral('/admin'), false));
        // Raw form as written: the value normalises to `/` but the raw path matches literally.
        $this->assertTrue(PathMatcher::equals(PathNormalizer::analyze('/x/..'), PathMatcher::compileLiteral('/x/..'), false));
        $this->assertTrue(PathMatcher::startsWith(PathNormalizer::analyze('/admin\\..\\public'), PathMatcher::compileLiteral('/admin'), false));
        $this->assertFalse(PathMatcher::startsWith(PathNormalizer::analyze('/api'), PathMatcher::compileLiteral('/admin'), false));
    }

    public function testPermissiveModeRefusesAmbiguousPaths(): void
    {
        $public = PathMatcher::compileLiteral('/public/');

        $this->assertTrue(PathMatcher::startsWith(PathNormalizer::analyze('/%70ublic/x'), $public, true));
        $this->assertFalse(PathMatcher::startsWith(PathNormalizer::analyze('/admin/../public/x'), $public, true));
        $this->assertFalse(PathMatcher::equals(PathNormalizer::analyze('/public//'), $public, true));
        $this->assertFalse(PathMatcher::matchesRegex(PathNormalizer::analyze('/public/./x'), static fn(string $subject): bool => true, true));
    }

    public function testEmptyPrefixNeverMatches(): void
    {
        $empty = PathMatcher::compileLiteral('');
        $this->assertFalse(PathMatcher::startsWith(PathNormalizer::analyze('/anything'), $empty, false));
        $this->assertFalse(PathMatcher::startsWith(PathNormalizer::analyze('/anything'), $empty, true));
    }

    public function testRestrictiveRegexChecksRawOnlyWhenItDiffers(): void
    {
        $subjects = [];
        $record = static function (string $subject) use (&$subjects): bool {
            $subjects[] = $subject;
            return false;
        };

        PathMatcher::matchesRegex(PathNormalizer::analyze('/plain'), $record, false);
        $this->assertSame(['/plain'], $subjects);

        $subjects = [];
        PathMatcher::matchesRegex(PathNormalizer::analyze('/%70lain'), $record, false);
        $this->assertSame(['/plain', '/%70lain'], $subjects);
    }
}
