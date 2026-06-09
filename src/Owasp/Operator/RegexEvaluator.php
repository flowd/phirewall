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
 * Values exceeding {@see RegexMatcher::MAX_SUBJECT_LENGTH} bytes are truncated to that length
 * and the head is inspected, bounding regex work on attacker-controlled input without letting a
 * payload evade detection simply by padding past the limit. A subject that triggers a PCRE engine
 * error (malformed UTF-8 under the /u flag, backtrack/recursion limit) is treated as a match so a
 * crafted value cannot disable a rule by forcing the error.
 */
final readonly class RegexEvaluator implements OperatorEvaluatorInterface
{
    /** Cached regex pattern with delimiters, ready for preg_match(). */
    private string $delimitedPattern;

    /** Whether the delimited pattern itself compiles; a broken pattern can never match. */
    private bool $patternCompiles;

    public function __construct(string $pattern)
    {
        $this->delimitedPattern = self::wrapInTildeDelimiters($pattern);
        $this->patternCompiles = @preg_match($this->delimitedPattern, '') !== false;
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        // A non-compiling pattern cannot match; treating it as a match would make one broken
        // rule block every request. The breakage surfaces when the rule is loaded, not per request.
        if (!$this->patternCompiles) {
            return false;
        }

        foreach ($values as $value) {
            if (strlen($value) > RegexMatcher::MAX_SUBJECT_LENGTH) {
                // Byte truncation can split a trailing multi-byte UTF-8 sequence, which would make
                // an otherwise-valid subject fail the /u match and be wrongly treated as a match.
                // Drop the partial trailing sequence so a valid long input is not falsely blocked;
                // a subject malformed before the boundary still fails closed below.
                $value = $this->trimPartialTrailingUtf8(substr($value, 0, RegexMatcher::MAX_SUBJECT_LENGTH));
            }

            // Pattern compiles, so anything other than a definite no-match (0) is either a real
            // match or a subject-induced engine error; both fail closed to a match.
            if (@preg_match($this->delimitedPattern, $value) !== 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Drop an incomplete trailing UTF-8 sequence left by byte truncation. A UTF-8 character is at
     * most 4 bytes, so at most 3 trailing bytes can form a partial sequence; a subject that stays
     * invalid after trimming is malformed before the boundary and is left to fail closed.
     */
    private function trimPartialTrailingUtf8(string $value): string
    {
        for ($dropped = 0; $dropped < 3 && $value !== '' && @preg_match('//u', $value) !== 1; ++$dropped) {
            $value = substr($value, 0, -1);
        }

        return $value;
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
