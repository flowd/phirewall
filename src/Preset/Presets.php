<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Preset;

use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;

/**
 * Ready-to-use rule bundles for common protection scenarios.
 *
 * Each preset is a {@see PortableConfig} — plain, inspectable, JSON-serializable
 * data rather than opaque closures. Materialize one (or several) on your own
 * cache with {@see \Flowd\Phirewall\Config::combine()}; presets never receive a
 * cache themselves, keeping shareable rule data decoupled from the stateful
 * counter store:
 *
 * ```php
 * // A preset on its own:
 * $config = (new Config($cache))->combine(Presets::apiRateLimiting());
 *
 * // A preset layered with your own portable rules (later args win by name):
 * $config = (new Config($cache))->combine(Presets::loginProtection(), $myPortable);
 *
 * // Several presets stacked together:
 * $config = (new Config($cache))->combine(
 *     Presets::scannerBlocking(),
 *     Presets::sensitivePathBlocking(),
 *     Presets::apiRateLimiting(),
 * );
 * ```
 *
 * Every rule is namespaced under a `preset.<area>.*` name so a later layer that
 * redefines the rule by name overrides it predictably, and every accessor
 * returns a FRESH instance — the presets themselves are immutable and stateless.
 *
 * ## Assumed conventions
 *
 *  - `apiRateLimiting()` scopes its throttles to the `/api` path prefix.
 *  - `loginProtection()` scopes its login throttle to the `/login` path prefix
 *    and counts a brute-force failure only when the handler calls
 *    `RequestContext::recordFailure(Presets::LOGIN_FAILURE_RULE)` after a failed
 *    authentication. The fail2ban rule deliberately uses a never-match filter,
 *    so it cannot be tripped by any spoofable request property; bans are driven
 *    exclusively by that trusted post-handler signal.
 *
 * Override any of these by combining the preset with your own portable schema
 * that redefines the rule by name.
 *
 * ## Keys and proxies
 *
 * IP-keyed rules resolve the client from `REMOTE_ADDR` (proxy headers are not
 * trusted by default). Behind a load balancer or CDN, `REMOTE_ADDR` is the
 * proxy, so a preset's IP-keyed throttle/ban would bucket every client together.
 * For those deployments, layer your own throttle keyed on a trusted client IP
 * (see `KeyExtractors::clientIp()` with a `TrustedProxyResolver`) or on the
 * authenticated principal, overriding the preset rule by name.
 */
final class Presets
{
    /**
     * Version of the bundled preset catalogue. Bumped whenever a preset's rule
     * set changes in a way integrators should review. Pair it with a
     * {@see PresetUpdateChecker} to surface "a newer ruleset is available".
     */
    public const VERSION = '1.0.0';

    public const API_RATE_LIMITING = 'api-rate-limiting';

    public const LOGIN_PROTECTION = 'login-protection';

    public const SCANNER_BLOCKING = 'scanner-blocking';

    public const SENSITIVE_PATH_BLOCKING = 'sensitive-path-blocking';

    /**
     * Path prefix the API rate-limiting throttles are scoped to.
     */
    public const API_PATH_PREFIX = '/api';

    /**
     * Path prefix the login throttle is scoped to.
     */
    public const LOGIN_PATH_PREFIX = '/login';

    /**
     * fail2ban rule name used by {@see loginProtection()}. Pass it to
     * `RequestContext::recordFailure()` from your login handler.
     */
    public const LOGIN_FAILURE_RULE = 'preset.login.bruteforce';

    /**
     * The catalogue version. Convenience accessor mirroring {@see VERSION} for
     * callers holding a `Presets` reference or comparing against a checker.
     */
    public static function version(): string
    {
        return self::VERSION;
    }

    /**
     * All shipped preset name constants.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return [
            self::API_RATE_LIMITING,
            self::LOGIN_PROTECTION,
            self::SCANNER_BLOCKING,
            self::SENSITIVE_PATH_BLOCKING,
        ];
    }

    // ── API rate limiting ────────────────────────────────────────────────

    /**
     * Per-client sliding-window rate limiting for API traffic.
     *
     * Two windows guard the `/api` path prefix, both keyed on the client IP:
     *  - `preset.api.burst` — 20 requests / 1s (anti-hammer ceiling)
     *  - `preset.api.sustained` — 300 requests / 60s (sustained average)
     *
     * Requests outside `/api` are untouched by these rules.
     */
    public static function apiRateLimiting(): PortableConfig
    {
        $scope = PortableConfig::filterPathPrefix(self::API_PATH_PREFIX);

        return PortableConfig::create()
            ->throttle('preset.api.burst', limit: 20, period: 1, key: PortableConfig::keyIp(), sliding: true, scope: $scope)
            ->throttle('preset.api.sustained', limit: 300, period: 60, key: PortableConfig::keyIp(), sliding: true, scope: $scope);
    }

    // ── Login protection ─────────────────────────────────────────────────

    /**
     * Brute-force protection for authentication endpoints.
     *
     *  - `preset.login.throttle` — 10 attempts / 60s per IP on the `/login`
     *    path prefix (sliding), slowing attackers before a ban kicks in.
     *  - `preset.login.bruteforce` — fail2ban: ban the client IP for 15 minutes
     *    after 5 failures within 15 minutes.
     *
     * A failure is counted only when your login handler calls
     * `RequestContext::recordFailure(Presets::LOGIN_FAILURE_RULE)` after a failed
     * authentication; the recorded-signal path bans on the rule's IP key. The
     * fail2ban rule uses a never-match filter on purpose: counting failures from
     * a client-controlled marker header would let an attacker forge that header
     * to drive failures for any `REMOTE_ADDR` and — behind a shared proxy/CDN —
     * ban the proxy IP, locking out every user.
     */
    public static function loginProtection(): PortableConfig
    {
        return PortableConfig::create()
            ->throttle(
                'preset.login.throttle',
                limit: 10,
                period: 60,
                key: PortableConfig::keyIp(),
                sliding: true,
                scope: PortableConfig::filterPathPrefix(self::LOGIN_PATH_PREFIX),
            )
            ->fail2ban(
                self::LOGIN_FAILURE_RULE,
                threshold: 5,
                period: 900,
                ban: 900,
                // Never matched pre-handler: a brute-force failure must not be
                // assertable from any client-controlled request property (a
                // forgeable marker header would let an attacker drive failures
                // for an arbitrary REMOTE_ADDR — behind a shared proxy/CDN that
                // bans the proxy IP and locks out everyone). Failures are
                // recorded post-authentication via
                // RequestContext::recordFailure(self::LOGIN_FAILURE_RULE),
                // which bypasses the filter and bans on the rule's IP key.
                filter: PortableConfig::filterNone(),
                key: PortableConfig::keyIp(),
            );
    }

    // ── Scanner blocking ─────────────────────────────────────────────────

    /**
     * Block automated attack tooling.
     *
     *  - `preset.scanner.known-tools` — blocks requests whose User-Agent matches
     *    a known scanner / exploit tool (sqlmap, nikto, nmap, nuclei, …).
     *  - `preset.scanner.suspicious-headers` — blocks requests missing the
     *    standard browser `Accept` / `Accept-Language` / `Accept-Encoding`
     *    headers.
     *
     * Note: the suspicious-headers rule is the more aggressive of the two —
     * some legitimate API clients, privacy tools, and embedded browsers omit
     * those headers. If your traffic includes non-browser clients, override or
     * drop `preset.scanner.suspicious-headers` by name when combining.
     */
    public static function scannerBlocking(): PortableConfig
    {
        return PortableConfig::create()
            ->blocklist('preset.scanner.known-tools', PortableConfig::filterKnownScanners())
            ->blocklist('preset.scanner.suspicious-headers', PortableConfig::filterSuspiciousHeaders());
    }

    // ── Sensitive path blocking ──────────────────────────────────────────

    /**
     * Block probes for sensitive files and directories that should never be
     * publicly reachable (VCS metadata, dotfiles, credential stores).
     *
     * Backed by a single pattern blocklist `preset.sensitive-path.probes`. The
     * patterns are deliberately high-signal / low-false-positive: no normal
     * application serves `/.git/…`, `/.env`, `/.aws/credentials`, or `/.htpasswd`.
     */
    public static function sensitivePathBlocking(): PortableConfig
    {
        return PortableConfig::create()
            ->patternBlocklist('preset.sensitive-path.probes', [
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.git(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.svn(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.hg(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.env(\.[A-Za-z0-9_.-]+)?$#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.aws/credentials(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.htpasswd(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.htaccess(/|$)#'),
                PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.DS_Store(/|$)#'),
            ]);
    }

    // ── Generic access by name ───────────────────────────────────────────

    /**
     * Resolve a preset's portable schema by its name constant.
     *
     * @param string $preset One of the {@see names()} constants.
     * @throws \InvalidArgumentException When the name is not a known preset.
     */
    public static function get(string $preset): PortableConfig
    {
        return match ($preset) {
            self::API_RATE_LIMITING => self::apiRateLimiting(),
            self::LOGIN_PROTECTION => self::loginProtection(),
            self::SCANNER_BLOCKING => self::scannerBlocking(),
            self::SENSITIVE_PATH_BLOCKING => self::sensitivePathBlocking(),
            default => throw new \InvalidArgumentException(sprintf('Unknown preset "%s".', $preset)),
        };
    }
}
