<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Canonicalises a request path before path rules match it.
 *
 * PSR-7 `UriInterface::getPath()` returns the path still percent-encoded and
 * with dot-segments intact, while web servers and routers decode and resolve
 * it. Matching the raw string lets `/%2eenv`, `/%61dmin/x` or `/./admin/x`
 * reach the same resource as `/.env` / `/admin/x` without matching a rule
 * written for it. Every built-in path rule therefore matches the normalised
 * path produced here.
 *
 * ## Rules, in order
 *
 * 1. **Empty path** becomes `/` (an absolute URI without a path is the root).
 * 2. **Percent-decoding, exactly one pass** (`rawurldecode()`): `%2e` and
 *    `%2E` become `.`, `%252e` becomes the literal `%2e` (never `.`: no server
 *    in front of a PHP application double-decodes, and decoding twice would
 *    let a rule match something the application never sees). Invalid
 *    sequences such as `%zz` or a trailing `%` stay literal. `+` is not a
 *    space in a path and stays `+`.
 * 3. **NUL truncates.** The path is cut at the first decoded NUL byte, the
 *    reading a C-string based backend applies, so `/.env%00.png` is treated as
 *    `/.env`. NUL never reaches a regex subject. Other control characters are
 *    kept as-is: they are valid UTF-8 and change no path structure.
 * 4. **Invalid UTF-8 is re-encoded.** Bytes that do not form valid UTF-8
 *    after decoding are written back as uppercase `%XX`. The normalised path
 *    is therefore always valid UTF-8, so a `path_regex` with the `u` modifier
 *    cannot hit a PCRE UTF-8 error (which a fail-open matcher would turn into
 *    a silent no-match, i.e. a bypass). Overlong encodings such as `%c0%ae`
 *    stay encoded and are never read as `.`.
 * 5. **A missing leading `/` is added.**
 * 6. **Encoded slashes are separators.** `%2f` decodes to `/` in step 2 and is
 *    treated like any other `/`. Servers differ (Apache rejects it by default,
 *    nginx decodes it and resolves dot-segments across it, Symfony/Laravel
 *    routers decode it before routing), and treating it as a separator is the
 *    reading under which a blocklist cannot be sidestepped.
 * 7. **Backslash is NOT a separator.** nginx, Apache, Caddy, the PHP built-in
 *    server and PHP routers treat `\` as an ordinary character. Converting it
 *    would make `\..\` act as a dot-segment the application does not honour,
 *    which can move a request OUT of a blocked prefix (`/admin\..\public`
 *    would normalise to `/public`). On IIS / Windows backends that do treat
 *    `\` as a separator, write rules as regexes matching `[/\\]`.
 * 8. **Duplicate slashes collapse** (`//` to `/`), before dot-segment removal,
 *    which is the filesystem and nginx `merge_slashes` reading.
 * 9. **Dot-segments are removed** per RFC 3986 section 5.2.4, after decoding,
 *    so `%2e%2e` segments count: `/a/./b` is `/a/b`, `/a/../b` is `/b`, and
 *    `..` never climbs above the root (`/../../x` is `/x`).
 *
 * Deliberately left alone:
 *
 * - **Case.** Paths are case-sensitive on most servers and operator rules rely
 *   on case. On a case-insensitive filesystem `/.ENV` can serve `/.env`; cover
 *   that with an `i`-flagged `path_regex` where it matters.
 * - **Trailing slash.** `/admin` and `/admin/` stay distinct (they are distinct
 *   resources on most servers; some routers fold them). Use a prefix or a
 *   regex such as `#^/admin/?$#` when both must match.
 * - **Path parameters** (`;jsessionid=...`). Java servlet containers strip
 *   them, PHP stacks do not; they stay part of the path. A prefix rule still
 *   matches `/admin;x/...`.
 *
 * ## Ambiguity and safelists
 *
 * The normalised path is the safer reading for rules that RESTRICT a request
 * (blocklists, fail2ban/allow2ban filters, throttle scopes, tracks): matching
 * more there blocks or counts more. Those rules match when either the
 * normalised or the raw path matches, so a rule written against the raw form
 * (a regex looking for `%2e%2e` or `..`) keeps working.
 *
 * For a rule that GRANTS something (a safelist skips every other rule)
 * over-matching is the unsafe direction: `/admin/../public` or
 * `/admin%2f..%2fpublic` normalise to `/public`, but a router that does not
 * resolve dot-segments may dispatch them to an `/admin/{any}` route. The raw
 * path is no better (`/public/../admin` starts with `/public`). So
 * {@see analyze()} flags a path as ambiguous when it contains a construct
 * servers disagree on: a dot-segment, an encoded slash, a backslash
 * (literal or `%5c`), duplicate slashes, a control character, invalid UTF-8,
 * or no leading `/`. Safelist path filters never match an ambiguous path.
 * Plain decoding of other characters (`%61` to `a`, `%20` to a space) is not
 * ambiguous: RFC 3986 makes those equivalent.
 */
final class PathNormalizer
{
    /** Single-entry memo: rules evaluated for one request share the analysis. */
    private static ?NormalizedPath $last = null;

    /**
     * The normalised form of a path (see the class docblock for the rules).
     */
    public static function normalize(string $path): string
    {
        return self::compute($path)->normalized;
    }

    /**
     * The normalised form of the request's URI path.
     */
    public static function fromRequest(ServerRequestInterface $serverRequest): NormalizedPath
    {
        return self::analyze($serverRequest->getUri()->getPath());
    }

    /**
     * The raw path, its normalised form, and whether it is ambiguous.
     */
    public static function analyze(string $path): NormalizedPath
    {
        $last = self::$last;
        if ($last instanceof NormalizedPath && $last->raw === $path) {
            return $last;
        }

        return self::$last = self::compute($path);
    }

    private static function compute(string $raw): NormalizedPath
    {
        if ($raw === '') {
            return new NormalizedPath($raw, '/', false);
        }

        $ambiguous = !str_starts_with($raw, '/')
            || stripos($raw, '%2f') !== false
            || stripos($raw, '%5c') !== false
            || str_contains($raw, '\\');

        $path = rawurldecode($raw);

        $nul = strpos($path, "\0");
        if ($nul !== false) {
            $path = substr($path, 0, $nul);
            $ambiguous = true;
        }

        if (preg_match('/[\x01-\x1F\x7F]/', $path) === 1) {
            $ambiguous = true;
        }

        if (preg_match('//u', $path) !== 1) {
            $path = self::reencodeInvalidUtf8($path);
            $ambiguous = true;
        }

        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }

        $collapsed = (string) preg_replace('#/{2,}#', '/', $path);
        if ($collapsed !== $path) {
            $ambiguous = true;
        }

        [$path, $hadDotSegments] = self::removeDotSegments($collapsed);

        return new NormalizedPath($raw, $path, $ambiguous || $hadDotSegments);
    }

    /**
     * RFC 3986 section 5.2.4 on an absolute path whose slashes are already
     * collapsed. Returns the resolved path and whether a `.` or `..` segment
     * was present.
     *
     * @return array{string, bool}
     */
    private static function removeDotSegments(string $path): array
    {
        $segments = explode('/', substr($path, 1));
        $output = [];
        $hadDotSegments = false;
        $lastIndex = count($segments) - 1;
        $trailingSlash = false;

        foreach ($segments as $index => $segment) {
            if ($segment === '.' || $segment === '..') {
                $hadDotSegments = true;
                if ($segment === '..') {
                    array_pop($output);
                }

                // A final dot-segment leaves a directory reference: `/a/..` is `/`, `/a/.` is `/a/`.
                if ($index === $lastIndex) {
                    $trailingSlash = true;
                }

                continue;
            }

            $output[] = $segment;
        }

        $result = '/' . implode('/', $output);
        if ($trailingSlash && !str_ends_with($result, '/')) {
            $result .= '/';
        }

        return [$result, $hadDotSegments];
    }

    private static function reencodeInvalidUtf8(string $path): string
    {
        // Consume runs of well-formed UTF-8; any other single byte is encoded.
        return (string) preg_replace_callback(
            '/(?:[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}'
            . '|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})+'
            . '|(.)/s',
            static fn(array $match): string => isset($match[1]) ? sprintf('%%%02X', ord($match[1])) : $match[0],
            $path,
        );
    }
}
