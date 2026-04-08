<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Store\QuotedIdentifier;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the QuotedIdentifier value object.
 */
final class QuotedIdentifierTest extends TestCase
{
    // ── Simple identifier quoting ────────────────────────────────────────

    public function testQuotesSimpleIdentifierWithDoubleQuotes(): void
    {
        $quoted = QuotedIdentifier::quote('my_table', '"');
        $this->assertSame('"my_table"', (string) $quoted);
    }

    public function testQuotesSimpleIdentifierWithBackticks(): void
    {
        $quoted = QuotedIdentifier::quote('my_table', '`');
        $this->assertSame('`my_table`', (string) $quoted);
    }

    // ── Dot-separated (schema.table) quoting ────────────────────────────

    public function testQuotesDotSeparatedIdentifierWithDoubleQuotes(): void
    {
        $quoted = QuotedIdentifier::quote('myschema.mytable', '"');
        $this->assertSame('"myschema"."mytable"', (string) $quoted);
    }

    public function testQuotesDotSeparatedIdentifierWithBackticks(): void
    {
        $quoted = QuotedIdentifier::quote('myschema.mytable', '`');
        $this->assertSame('`myschema`.`mytable`', (string) $quoted);
    }

    // ── Quote character escaping ────────────────────────────────────────

    public function testEscapesDoubleQuoteInIdentifier(): void
    {
        $quoted = QuotedIdentifier::quote('my"table', '"');
        $this->assertSame('"my""table"', (string) $quoted);
    }

    public function testEscapesBacktickInIdentifier(): void
    {
        $quoted = QuotedIdentifier::quote('my`table', '`');
        $this->assertSame('`my``table`', (string) $quoted);
    }

    public function testEscapesQuoteCharacterInDotSeparatedParts(): void
    {
        $quoted = QuotedIdentifier::quote('my"schema.my"table', '"');
        $this->assertSame('"my""schema"."my""table"', (string) $quoted);
    }

    // ── Stringable ──────────────────────────────────────────────────────

    public function testImplementsStringable(): void
    {
        $quoted = QuotedIdentifier::quote('test', '"');
        $this->assertSame('"test"', (string) $quoted);
    }

    public function testCanBeUsedInStringInterpolation(): void
    {
        $quoted = QuotedIdentifier::quote('cache_table', '"');
        $sql = "SELECT * FROM {$quoted}";
        $this->assertSame('SELECT * FROM "cache_table"', $sql);
    }
}
