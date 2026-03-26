<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values against a PCRE regular expression (@rx operator).
 */
final readonly class RegexEvaluator implements OperatorEvaluatorInterface
{
    /** Cached regex pattern with delimiters, ready for preg_match(). */
    private string $delimitedPattern;

    public function __construct(string $pattern)
    {
        $this->delimitedPattern = self::ensureRegexDelimiters($pattern);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        foreach ($values as $value) {
            if (@preg_match($this->delimitedPattern, $value) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Ensure the pattern has proper PCRE delimiters.
     * If pattern starts with a valid delimiter char and has a closing one, keep it.
     * Otherwise, wrap in '~' and escape unescaped '~'.
     */
    public static function ensureRegexDelimiters(string $pattern): string
    {
        // Valid delimiters: non-alphanumeric, non-whitespace, non-backslash,
        // and NOT bracket-style openers (these require matching closers: (), {}, [], <>).
        if ($pattern !== '' && preg_match('/^(.)(.*)\1[imsxuADSUXJ]*$/', $pattern) === 1) {
            $firstChar = $pattern[0];
            if (!ctype_alnum($firstChar) && !ctype_space($firstChar)
                && $firstChar !== '\\' && !in_array($firstChar, ['(', '{', '[', '<'], true)) {
                return $pattern;
            }
        }

        // Only escape unescaped tildes — str_replace would double-escape \~ into \\~
        $escaped = preg_replace('/(?<!\\\\)~/', '\~', $pattern);
        // Use Unicode mode by default to better mirror CRS behavior for text processing
        return '~' . $escaped . '~u';
    }
}
