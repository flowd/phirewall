<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values against a PCRE regular expression (@rx operator).
 */
final readonly class RegexEvaluator implements OperatorEvaluatorInterface
{
    /**
     * Maximum byte length of a value passed to preg_match() to guard against ReDoS attacks.
     *
     * Values exceeding this limit are skipped (treated as non-matching). This is an intentional
     * trade-off: extremely long payloads may evade regex detection, but the alternative — running
     * unbounded regex on attacker-controlled input — risks catastrophic backtracking that can
     * freeze the process. This mirrors standard WAF behavior (e.g., ModSecurity SecRequestBodyLimit).
     */
    private const MAX_VALUE_LENGTH = 8192;

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
            if (strlen($value) > self::MAX_VALUE_LENGTH) {
                continue;
            }

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

        // Escape unescaped tildes. A tilde is unescaped when preceded by an
        // even number (including zero) of backslashes. A simple negative lookbehind
        // fails for \\~ (even backslashes), so we use a callback that counts them.
        $escaped = preg_replace_callback(
            '/(\\\\*)(~)/',
            static function (array $matches): string {
                $backslashes = $matches[1];
                // Odd number of backslashes means the tilde is already escaped
                if (strlen($backslashes) % 2 !== 0) {
                    return $matches[0];
                }

                return $backslashes . '\~';
            },
            $pattern,
        );
        // Use Unicode mode by default to better mirror CRS behavior for text processing
        return '~' . $escaped . '~u';
    }
}
