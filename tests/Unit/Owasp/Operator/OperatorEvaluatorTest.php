<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Operator;

use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use Flowd\Phirewall\Owasp\Operator\ContainsEvaluator;
use Flowd\Phirewall\Owasp\Operator\EndsWithEvaluator;
use Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorFactory;
use Flowd\Phirewall\Owasp\Operator\PhraseMatchEvaluator;
use Flowd\Phirewall\Owasp\Operator\PhraseMatchFromFileEvaluator;
use Flowd\Phirewall\Owasp\Operator\RegexEvaluator;
use Flowd\Phirewall\Owasp\Operator\StartsWithEvaluator;
use Flowd\Phirewall\Owasp\Operator\StringEqualEvaluator;
use Flowd\Phirewall\Owasp\Operator\UnsupportedOperatorEvaluator;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class OperatorEvaluatorTest extends TestCase
{
    private const REGEX_MAX_SUBJECT_LENGTH = RegexMatcher::MAX_SUBJECT_LENGTH;

    // --- RegexEvaluator ---

    public function testRegexEvaluatorMatchesPattern(): void
    {
        $evaluator = new RegexEvaluator('^/admin\b');
        $this->assertTrue($evaluator->evaluate(['/admin/panel']));
        $this->assertFalse($evaluator->evaluate(['/user/admin']));
    }

    public function testRegexEvaluatorInvalidPatternReturnsFalse(): void
    {
        $evaluator = new RegexEvaluator('^/ad[min');
        $this->assertFalse($evaluator->evaluate(['/admin']));
    }

    public function testRegexEvaluatorDoesNotMatchPayloadBeyondMaxLength(): void
    {
        // Truncation still bounds inspection: content that only appears after the limit is
        // not seen, so a pattern matching only that tail does not fire.
        $evaluator = new RegexEvaluator('needle');
        $oversizedValue = str_repeat('a', self::REGEX_MAX_SUBJECT_LENGTH) . 'needle';
        $this->assertFalse($evaluator->evaluate([$oversizedValue]));
    }

    public function testRegexEvaluatorMatchesWithinLengthLimit(): void
    {
        $evaluator = new RegexEvaluator('hello');
        $valueWithinLimit = str_repeat('a', 100) . 'hello';
        $this->assertTrue($evaluator->evaluate([$valueWithinLimit]));
    }

    public function testRegexEvaluatorMatchesAtExactlyMaxLength(): void
    {
        $evaluator = new RegexEvaluator('a');
        $exactLimitValue = str_repeat('a', self::REGEX_MAX_SUBJECT_LENGTH);
        $this->assertTrue($evaluator->evaluate([$exactLimitValue]));
    }

    public function testRegexEvaluatorTreatsEngineErrorOnMalformedUtf8AsMatch(): void
    {
        // The pattern compiles, so a false result from preg_match is a subject-induced
        // engine error (malformed UTF-8 under the /u flag). A crafted value must not be
        // able to disable the rule by forcing that error.
        $evaluator = new RegexEvaluator('select.*from');
        $malformedSubject = "select \xff\xfe from users";

        $this->assertTrue($evaluator->evaluate([$malformedSubject]));
    }

    public function testRegexEvaluatorInspectsHeadOfOversizedValue(): void
    {
        // A payload within the first MAX_SUBJECT_LENGTH bytes must be inspected even when
        // the value is padded past the limit.
        $evaluator = new RegexEvaluator('attack');
        $paddedValue = 'attack' . str_repeat('A', self::REGEX_MAX_SUBJECT_LENGTH);

        $this->assertTrue($evaluator->evaluate([$paddedValue]));
    }

    public function testRegexEvaluatorStillMatchesShorterValueWhenOverlengthPresent(): void
    {
        $evaluator = new RegexEvaluator('match');
        $oversized = str_repeat('x', self::REGEX_MAX_SUBJECT_LENGTH + 1) . 'match';
        $normal = 'this should match';
        $this->assertTrue($evaluator->evaluate([$oversized, $normal]));
    }

    public function testRegexEvaluatorWrapsBarePattern(): void
    {
        $delimited = RegexEvaluator::wrapInTildeDelimiters('^admin');
        $this->assertSame('~^admin~u', $delimited);
    }

    public function testRegexEvaluatorWrapsPatternWithLiteralSlashes(): void
    {
        // CRS @rx patterns are bare PCRE content, so leading/trailing slashes are literal,
        // not delimiters. The wrapper must keep them inside the body.
        $delimited = RegexEvaluator::wrapInTildeDelimiters('/^test$/i');
        $this->assertSame('~/^test$/i~u', $delimited);
    }

    public function testRegexEvaluatorEscapesTildeInPattern(): void
    {
        $delimited = RegexEvaluator::wrapInTildeDelimiters('foo~bar');
        $this->assertSame('~foo\~bar~u', $delimited);
    }

    public function testRegexEvaluatorPreservesAlreadyEscapedTilde(): void
    {
        // Input: foo + 1 backslash + tilde (odd=1: tilde is escaped)
        $input = "foo\x5C~bar";
        $delimited = RegexEvaluator::wrapInTildeDelimiters($input);
        // Output: ~foo + 1 backslash + tilde + bar~u (unchanged)
        $this->assertSame("~foo\x5C~bar~u", $delimited);
    }

    public function testRegexEvaluatorEscapesTildeAfterEvenBackslashes(): void
    {
        // Input: foo + 2 backslashes + tilde (even=2: backslashes escape each other, tilde is unescaped)
        $input = "foo\x5C\x5C~bar";
        $delimited = RegexEvaluator::wrapInTildeDelimiters($input);
        // Output: ~foo + 2 backslashes + escaped tilde (3 backslashes + tilde) + bar~u
        $this->assertSame("~foo\x5C\x5C\x5C~bar~u", $delimited);
    }

    public function testRegexEvaluatorPreservesTildeAfterOddBackslashes(): void
    {
        // Input: foo + 3 backslashes + tilde (odd=3: last backslash escapes tilde)
        $input = "foo\x5C\x5C\x5C~bar";
        $delimited = RegexEvaluator::wrapInTildeDelimiters($input);
        // Output: ~foo + 3 backslashes + tilde + bar~u (unchanged)
        $this->assertSame("~foo\x5C\x5C\x5C~bar~u", $delimited);
    }

    // --- ContainsEvaluator ---

    public function testContainsEvaluatorCaseInsensitiveMatch(): void
    {
        $evaluator = new ContainsEvaluator('admin');
        $this->assertTrue($evaluator->evaluate(['/ADMIN/panel']));
        $this->assertFalse($evaluator->evaluate(['/user']));
    }

    public function testContainsEvaluatorEmptyNeedleReturnsFalse(): void
    {
        $evaluator = new ContainsEvaluator('');
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    // --- StringEqualEvaluator ---

    public function testStringEqualEvaluatorCaseInsensitiveMatch(): void
    {
        $evaluator = new StringEqualEvaluator('POST');
        $this->assertTrue($evaluator->evaluate(['post']));
        $this->assertTrue($evaluator->evaluate(['POST']));
        $this->assertFalse($evaluator->evaluate(['GET']));
    }

    // --- StartsWithEvaluator ---

    public function testStartsWithEvaluatorCaseInsensitiveMatch(): void
    {
        $evaluator = new StartsWithEvaluator('/admin');
        $this->assertTrue($evaluator->evaluate(['/Admin/panel']));
        $this->assertFalse($evaluator->evaluate(['/user/admin']));
    }

    public function testStartsWithEvaluatorEmptyPrefixReturnsFalse(): void
    {
        $evaluator = new StartsWithEvaluator('');
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    // --- EndsWithEvaluator ---

    public function testEndsWithEvaluatorCaseInsensitiveMatch(): void
    {
        $evaluator = new EndsWithEvaluator('.PHP');
        $this->assertTrue($evaluator->evaluate(['/index.php']));
        $this->assertFalse($evaluator->evaluate(['/index.php7']));
    }

    public function testEndsWithEvaluatorEmptySuffixReturnsFalse(): void
    {
        $evaluator = new EndsWithEvaluator('');
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    // --- PhraseMatchEvaluator ---

    public function testPhraseMatchEvaluatorMatchesAnyPhrase(): void
    {
        $evaluator = new PhraseMatchEvaluator('admin, secret, token');
        $this->assertTrue($evaluator->evaluate(['/admin/path']));
        $this->assertTrue($evaluator->evaluate(['/has-secret']));
        $this->assertFalse($evaluator->evaluate(['/safe/path']));
    }

    public function testPhraseMatchEvaluatorCaseInsensitive(): void
    {
        $evaluator = new PhraseMatchEvaluator('ADMIN');
        $this->assertTrue($evaluator->evaluate(['/admin']));
    }

    public function testPhraseMatchEvaluatorEmptyListReturnsFalse(): void
    {
        $evaluator = new PhraseMatchEvaluator('');
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    // --- PhraseMatchFromFileEvaluator ---

    public function testPhraseMatchFromFileEvaluatorLoadsAndMatches(): void
    {
        $root = vfsStream::setup('rules');
        vfsStream::newFile('phrases.txt')->at($root)->setContent("admin\nsecret\n");
        $file = $root->getChild('phrases.txt')->url();

        $evaluator = new PhraseMatchFromFileEvaluator($file);
        $this->assertTrue($evaluator->evaluate(['/admin/path']));
        $this->assertFalse($evaluator->evaluate(['/safe']));
    }

    public function testPhraseMatchFromFileEvaluatorMissingFileReturnsFalse(): void
    {
        $evaluator = new PhraseMatchFromFileEvaluator('/nonexistent/path.txt');
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    public function testPhraseMatchFromFileEvaluatorRejectsPathTraversal(): void
    {
        $evaluator = new PhraseMatchFromFileEvaluator('../../etc/passwd');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Path traversal detected');
        $evaluator->evaluate(['test']);
    }

    public function testPhraseMatchFromFileEvaluatorUsesContextFolder(): void
    {
        $root = vfsStream::setup('rules');
        $subdir = vfsStream::newDirectory('sub')->at($root);
        vfsStream::newFile('words.txt')->at($subdir)->setContent("blocked\n");

        $evaluator = new PhraseMatchFromFileEvaluator('words.txt', $root->url() . '/sub');
        $this->assertTrue($evaluator->evaluate(['/blocked-content']));
    }

    public function testPhraseMatchFromFileEvaluatorRejectsAbsoluteOperandWithContextFolder(): void
    {
        $root = vfsStream::setup('rules');
        vfsStream::newDirectory('sub')->at($root);

        $evaluator = new PhraseMatchFromFileEvaluator('/etc/passwd', $root->url() . '/sub');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Absolute path not permitted');
        $evaluator->evaluate(['test']);
    }

    public function testPhraseMatchFromFileEvaluatorRejectsWindowsAbsoluteOperandWithContextFolder(): void
    {
        $root = vfsStream::setup('rules');
        vfsStream::newDirectory('sub')->at($root);

        $evaluator = new PhraseMatchFromFileEvaluator('C:\\Windows\\System32\\drivers\\etc\\hosts', $root->url() . '/sub');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Absolute path not permitted');
        $evaluator->evaluate(['test']);
    }

    public function testPhraseMatchFromFileEvaluatorRejectsUncAbsoluteOperandWithContextFolder(): void
    {
        $root = vfsStream::setup('rules');
        vfsStream::newDirectory('sub')->at($root);

        $evaluator = new PhraseMatchFromFileEvaluator('\\\\server\\share\\phrases.txt', $root->url() . '/sub');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Absolute path not permitted');
        $evaluator->evaluate(['test']);
    }

    public function testPhraseMatchFromFileEvaluatorConfinementRejectsResolvedEscape(): void
    {
        // The realpath()-based confinement branch in loadPhrases() cannot be
        // driven through evaluate() under vfsStream (realpath() returns false on
        // vfs:// streams, so the branch is skipped). The boundary decision the
        // evaluator owns is therefore verified directly: a relative operand that
        // resolves (e.g. via a symlink) OUTSIDE the context folder must be
        // rejected, while one resolving inside is kept.
        $evaluator = new PhraseMatchFromFileEvaluator('words.txt');
        $isWithinContext = new \ReflectionMethod(PhraseMatchFromFileEvaluator::class, 'isWithinContext');

        // Resolved inside the context folder -> contained.
        $this->assertTrue($isWithinContext->invoke($evaluator, '/srv/rules/sub/words.txt', '/srv/rules/sub'));
        // Resolved to the context folder itself -> contained.
        $this->assertTrue($isWithinContext->invoke($evaluator, '/srv/rules/sub', '/srv/rules/sub'));
        // Symlink escape to a sibling directory -> rejected (caller throws).
        $this->assertFalse($isWithinContext->invoke($evaluator, '/srv/rules/other/words.txt', '/srv/rules/sub'));
        // Escape to a parent / unrelated tree -> rejected.
        $this->assertFalse($isWithinContext->invoke($evaluator, '/etc/passwd', '/srv/rules/sub'));
        // Sibling sharing a name prefix must NOT be mistaken for nested.
        $this->assertFalse($isWithinContext->invoke($evaluator, '/srv/rules/sub-evil/words.txt', '/srv/rules/sub'));
    }

    public function testPhraseMatchFromFileEvaluatorSkipsComments(): void
    {
        $root = vfsStream::setup('rules');
        $content = "# this is a comment\nadmin\n# another comment\n";
        vfsStream::newFile('phrases.txt')->at($root)->setContent($content);
        $file = $root->getChild('phrases.txt')->url();

        $evaluator = new PhraseMatchFromFileEvaluator($file);
        $this->assertTrue($evaluator->evaluate(['/admin']));
        $this->assertFalse($evaluator->evaluate(['/comment']));
    }

    // --- UnsupportedOperatorEvaluator ---

    public function testUnsupportedOperatorAlwaysReturnsFalse(): void
    {
        $evaluator = new UnsupportedOperatorEvaluator();
        $this->assertFalse($evaluator->evaluate(['anything']));
        $this->assertFalse($evaluator->evaluate([]));
    }

    // --- OperatorEvaluatorFactory ---

    public function testFactoryCreatesCorrectEvaluators(): void
    {
        $this->assertInstanceOf(RegexEvaluator::class, OperatorEvaluatorFactory::create('@rx', 'pattern'));
        $this->assertInstanceOf(ContainsEvaluator::class, OperatorEvaluatorFactory::create('@contains', 'needle'));
        $this->assertInstanceOf(StringEqualEvaluator::class, OperatorEvaluatorFactory::create('@streq', 'expected'));
        $this->assertInstanceOf(StartsWithEvaluator::class, OperatorEvaluatorFactory::create('@startswith', 'prefix'));
        $this->assertInstanceOf(StartsWithEvaluator::class, OperatorEvaluatorFactory::create('@beginswith', 'prefix'));
        $this->assertInstanceOf(EndsWithEvaluator::class, OperatorEvaluatorFactory::create('@endswith', 'suffix'));
        $this->assertInstanceOf(PhraseMatchEvaluator::class, OperatorEvaluatorFactory::create('@pm', 'phrase'));
        $this->assertInstanceOf(PhraseMatchFromFileEvaluator::class, OperatorEvaluatorFactory::create('@pmFromFile', 'file.txt'));
        $this->assertInstanceOf(UnsupportedOperatorEvaluator::class, OperatorEvaluatorFactory::create('@unknown', ''));
    }

    public function testFactoryIsCaseInsensitive(): void
    {
        $this->assertInstanceOf(RegexEvaluator::class, OperatorEvaluatorFactory::create('@RX', 'pattern'));
        $this->assertInstanceOf(ContainsEvaluator::class, OperatorEvaluatorFactory::create('@Contains', 'needle'));
    }

    public function testFactoryPassesContextFolderToPmFromFile(): void
    {
        $root = vfsStream::setup('rules');
        $subdir = vfsStream::newDirectory('sub')->at($root);
        vfsStream::newFile('words.txt')->at($subdir)->setContent("blocked\n");

        $evaluator = OperatorEvaluatorFactory::create('@pmFromFile', 'words.txt', $root->url() . '/sub');
        $this->assertInstanceOf(PhraseMatchFromFileEvaluator::class, $evaluator);
        $this->assertTrue($evaluator->evaluate(['/blocked-content']));
    }
}
