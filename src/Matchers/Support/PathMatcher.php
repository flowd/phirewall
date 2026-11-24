<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers\Support;

use Flowd\Phirewall\Http\NormalizedPath;
use Flowd\Phirewall\Http\PathNormalizer;

/**
 * Path comparisons on a {@see NormalizedPath}, shared by every built-in path rule.
 *
 * Literal rule values (exact paths, prefixes) are normalised once at compile
 * time with {@see compileLiteral()}, so `'/my%20file'` and `'/my file'` match
 * the same requests. Regex patterns cannot be normalised; they run against
 * the normalised path (and, in restrictive mode, the raw path too).
 *
 * Two modes (see {@see PathNormalizer} for the reasoning):
 *
 * - **restrictive** (blocklists, fail2ban/allow2ban filters, throttle scopes,
 *   tracks): match when the normalised path matches the normalised rule value
 *   OR the raw path matches the rule value as written. Over-matching only
 *   blocks or counts more, and rules written against the raw form keep working.
 * - **permissive** (safelists): match only an unambiguous path, on its
 *   normalised form, so an attacker cannot steer an ambiguous path into a
 *   safelisted one.
 *
 * @internal Shared infrastructure for phirewall internals. Not part of the public API.
 */
final class PathMatcher
{
    /**
     * A literal rule value in both forms: as written and normalised.
     */
    public static function compileLiteral(string $value): NormalizedPath
    {
        return new NormalizedPath($value, $value === '' ? '' : PathNormalizer::normalize($value), false);
    }

    public static function equals(NormalizedPath $requestPath, NormalizedPath $value, bool $permissive): bool
    {
        if ($permissive) {
            return !$requestPath->ambiguous && $requestPath->normalized === $value->normalized;
        }

        return $requestPath->normalized === $value->normalized || $requestPath->raw === $value->raw;
    }

    /**
     * An empty prefix never matches (it would otherwise match every request).
     */
    public static function startsWith(NormalizedPath $requestPath, NormalizedPath $prefix, bool $permissive): bool
    {
        if ($prefix->raw === '') {
            return false;
        }

        if ($permissive) {
            return !$requestPath->ambiguous && str_starts_with($requestPath->normalized, $prefix->normalized);
        }

        return str_starts_with($requestPath->normalized, $prefix->normalized)
            || str_starts_with($requestPath->raw, $prefix->raw);
    }

    /**
     * @param callable(string): bool $matches Regex test on one subject, carrying the caller's failure policy.
     */
    public static function matchesRegex(NormalizedPath $normalizedPath, callable $matches, bool $permissive): bool
    {
        if ($permissive) {
            return !$normalizedPath->ambiguous && $matches($normalizedPath->normalized);
        }

        return $matches($normalizedPath->normalized)
            || ($normalizedPath->raw !== $normalizedPath->normalized && $matches($normalizedPath->raw));
    }
}
