<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Operator;

use Flowd\Phirewall\Owasp\Operator\PhraseListParser;
use PHPUnit\Framework\TestCase;

final class PhraseListParserTest extends TestCase
{
    public function testParsesCommaSeparatedPhrases(): void
    {
        $result = PhraseListParser::parse('alpha, beta, gamma');
        $this->assertSame(['alpha', 'beta', 'gamma'], $result);
    }

    public function testParsesSpaceSeparatedPhrases(): void
    {
        $result = PhraseListParser::parse('alpha beta gamma');
        $this->assertSame(['alpha', 'beta', 'gamma'], $result);
    }

    public function testParsesQuotedPhrases(): void
    {
        $result = PhraseListParser::parse('"hello world" \'foo bar\'');
        $this->assertSame(['hello world', 'foo bar'], $result);
    }

    public function testHandlesBackslashEscapesInQuotes(): void
    {
        $result = PhraseListParser::parse('"hello\\"world"');
        $this->assertSame(['hello"world'], $result);
    }

    public function testRemovesDuplicates(): void
    {
        $result = PhraseListParser::parse('alpha, alpha, beta, alpha');
        $this->assertSame(['alpha', 'beta'], $result);
    }

    public function testSkipsEmptyTokens(): void
    {
        $result = PhraseListParser::parse(',, alpha,, , beta ,,');
        $this->assertSame(['alpha', 'beta'], $result);
    }

    public function testEmptyInputReturnsEmptyArray(): void
    {
        $this->assertSame([], PhraseListParser::parse(''));
    }

    public function testRespectsMaxPhrasesLimit(): void
    {
        $phrases = [];
        for ($i = 0; $i < 5005; ++$i) {
            $phrases[] = 'p' . $i;
        }

        $result = PhraseListParser::parse(implode(',', $phrases));
        $this->assertCount(PhraseListParser::MAX_PHRASES, $result);
        $this->assertSame('p0', $result[0]);
        $this->assertSame('p4999', $result[4999]);
    }

    public function testMaxPhrasesConstantIs5000(): void
    {
        $this->assertSame(5000, PhraseListParser::MAX_PHRASES);
    }
}
