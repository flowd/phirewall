<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

/**
 * A database identifier (table or column name) that has been quoted
 * for safe use in SQL statements.
 *
 * This type ensures that identifiers interpolated into SQL strings
 * have been through the quoting process. Raw strings cannot be
 * substituted without going through the factory method.
 */
final readonly class QuotedIdentifier implements \Stringable
{
    private function __construct(
        private string $quoted,
    ) {
    }

    /**
     * Quote an identifier using the appropriate dialect.
     *
     * Handles dot-separated identifiers (e.g., "myschema.mytable") by quoting
     * each part individually, producing "myschema"."mytable" (or `myschema`.`mytable`).
     *
     * MySQL uses backticks, PostgreSQL and SQLite use ANSI double quotes.
     */
    public static function quote(string $identifier, string $quoteCharacter): self
    {
        if (str_contains($identifier, '.')) {
            $parts = array_map(
                static fn(string $part): string => self::quoteSingle($part, $quoteCharacter),
                explode('.', $identifier)
            );

            return new self(implode('.', $parts));
        }

        return new self(self::quoteSingle($identifier, $quoteCharacter));
    }

    public function __toString(): string
    {
        return $this->quoted;
    }

    private static function quoteSingle(string $identifier, string $quoteCharacter): string
    {
        return $quoteCharacter
            . str_replace($quoteCharacter, $quoteCharacter . $quoteCharacter, $identifier)
            . $quoteCharacter;
    }
}
