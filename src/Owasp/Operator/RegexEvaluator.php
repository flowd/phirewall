<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

use Flowd\Phirewall\Matchers\Support\RegexMatcher;

/**
 * Evaluates values against a PCRE regular expression (@rx operator).
 *
 * ModSecurity/CRS @rx patterns are bare PCRE content (never pre-delimited),
 * so the pattern is always wrapped in '~...~u' with any unescaped '~' escaped.
 * Previous versions also tried to auto-detect "already-delimited" patterns by
 * checking whether the first and last characters matched — this misfired on
 * real CRS rules whose patterns happen to start and end with the same literal
 * character (notably backticks in rule 942510), turning those characters into
 * PCRE delimiters and collapsing the rule to its inner alternation.
 *
 * Values exceeding {@see RegexMatcher::MAX_SUBJECT_LENGTH} bytes are skipped (treated as
 * non-matching). This is an intentional trade-off: extremely long payloads may evade regex
 * detection, but the alternative — running unbounded regex on attacker-controlled input — risks
 * catastrophic backtracking that can freeze the process. This mirrors standard WAF behavior
 * (e.g., ModSecurity SecRequestBodyLimit).
 */
final readonly class RegexEvaluator implements OperatorEvaluatorInterface
{
    /** Cached regex pattern with delimiters, ready for preg_match(). */
    private string $delimitedPattern;

    public function __construct(string $pattern)
    {
        $this->delimitedPattern = self::wrapInTildeDelimiters($pattern);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        foreach ($values as $value) {
            if (strlen($value) > RegexMatcher::MAX_SUBJECT_LENGTH) {
                continue;
            }

            if (@preg_match($this->delimitedPattern, $value) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Wrap a bare PCRE pattern in '~...~u' delimiters, escaping any unescaped '~'.
     *
     * This is the only correct transformation for ModSecurity @rx arguments, which
     * are bare PCRE content by spec.
     */
    public static function wrapInTildeDelimiters(string $pattern): string
    {
        // Escape unescaped tildes. A tilde is unescaped when preceded by an
        // even number (including zero) of backslashes. A simple negative lookbehind
        // fails for \\~ (even backslashes), so we use a callback that counts them.
        $escaped = preg_replace_callback(
            '/(\\\\*)(~)/',
            static function (array $matches): string {
                $backslashes = $matches[1];
                if (strlen($backslashes) % 2 !== 0) {
                    return $matches[0];
                }

                return $backslashes . '\~';
            },
            $pattern,
        );

        // preg_replace_callback() returns null only on a genuine PCRE engine error
        // (e.g., invalid UTF-8 in $pattern). Surface that loudly rather than letting
        // a null leak into the cached delimited pattern.
        if ($escaped === null) {
            throw new \RuntimeException(sprintf(
                'Failed to escape tildes in regex pattern: %s',
                preg_last_error_msg(),
            ));
        }

        // Unicode mode mirrors CRS behavior for text processing.
        return '~' . $escaped . '~u';
    }
}
