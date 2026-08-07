<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers\Support;

/**
 * Safe regex compilation and matching with length guards.
 *
 * @internal Shared infrastructure for phirewall internals. Not part of the public API.
 */
final class RegexMatcher
{
    public const MAX_PATTERN_LENGTH = 4096;

    public const MAX_SUBJECT_LENGTH = 8192;

    public static function compile(string $pattern): ?string
    {
        if (strlen($pattern) > self::MAX_PATTERN_LENGTH) {
            return null;
        }

        set_error_handler(static fn(): bool => true);
        try {
            $result = @preg_match($pattern, '');
            if ($result === false) {
                return null;
            }
        } finally {
            restore_error_handler();
        }

        return $pattern;
    }

    public static function matches(?string $pattern, string $subject): bool
    {
        if ($pattern === null) {
            return false;
        }

        if (strlen($subject) > self::MAX_SUBJECT_LENGTH) {
            $subject = substr($subject, 0, self::MAX_SUBJECT_LENGTH);
        }

        // Pattern was already validated in compile() — @-suppression is sufficient here
        return @preg_match($pattern, $subject) === 1;
    }

    /**
     * Blocklist match that fails closed on a PCRE engine error.
     *
     * A null pattern (compile failed) stays disabled and returns false. A live
     * engine error, such as the backtrack limit being exceeded on a
     * compile-valid pattern, counts as a match so an attacker cannot bypass a
     * block rule by forcing the error.
     */
    public static function matchesFailClosed(?string $pattern, string $subject): bool
    {
        if ($pattern === null) {
            return false;
        }

        if (strlen($subject) > self::MAX_SUBJECT_LENGTH) {
            $subject = substr($subject, 0, self::MAX_SUBJECT_LENGTH);
        }

        // 1 (match) and false (engine error) both count as a match; only a clean 0 does not.
        return @preg_match($pattern, $subject) !== 0;
    }
}
