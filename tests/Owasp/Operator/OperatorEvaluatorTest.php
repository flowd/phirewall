<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Operator;

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

    public function testEvaluateSkipsValuesExceedingMaxLength(): void
    {
        $evaluator = new RegexEvaluator('a');
        $oversizedValue = str_repeat('a', 8193);
        $this->assertFalse($evaluator->evaluate([$oversizedValue]));
    }

    public function testEvaluateMatchesWithinLengthLimit(): void
    {
        $evaluator = new RegexEvaluator('hello');
        $valueWithinLimit = str_repeat('a', 100) . 'hello';
        $this->assertTrue($evaluator->evaluate([$valueWithinLimit]));
    }

    public function testRegexEvaluatorPreservesDelimitedPattern(): void
    {
        $delimited = RegexEvaluator::ensureRegexDelimiters('/^test$/i');
        $this->assertSame('/^test$/i', $delimited);
    }

    public function testRegexEvaluatorWrapsUndelimitedPattern(): void
    {
        $delimited = RegexEvaluator::ensureRegexDelimiters('^admin');
        $this->assertSame('~^admin~u', $delimited);
    }

    public function testRegexEvaluatorEscapesTildeInPattern(): void
    {
        $delimited = RegexEvaluator::ensureRegexDelimiters('foo~bar');
        $this->assertSame('~foo\~bar~u', $delimited);
    }

    public function testRegexEvaluatorPreservesAlreadyEscapedTilde(): void
    {
        // Input: foo + 1 backslash + tilde (odd=1: tilde is escaped)
        $input = "foo\x5C~bar";
        $delimited = RegexEvaluator::ensureRegexDelimiters($input);
        // Output: ~foo + 1 backslash + tilde + bar~u (unchanged)
        $this->assertSame("~foo\x5C~bar~u", $delimited);
    }

    public function testRegexEvaluatorEscapesTildeAfterEvenBackslashes(): void
    {
        // Input: foo + 2 backslashes + tilde (even=2: backslashes escape each other, tilde is unescaped)
        $input = "foo\x5C\x5C~bar";
        $delimited = RegexEvaluator::ensureRegexDelimiters($input);
        // Output: ~foo + 2 backslashes + escaped tilde (3 backslashes + tilde) + bar~u
        $this->assertSame("~foo\x5C\x5C\x5C~bar~u", $delimited);
    }

    public function testRegexEvaluatorPreservesTildeAfterOddBackslashes(): void
    {
        // Input: foo + 3 backslashes + tilde (odd=3: last backslash escapes tilde)
        $input = "foo\x5C\x5C\x5C~bar";
        $delimited = RegexEvaluator::ensureRegexDelimiters($input);
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
