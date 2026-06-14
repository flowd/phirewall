<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Preset;

use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;

/**
 * Ready-to-use rule bundles for common protection scenarios.
 *
 * Each preset is a {@see PortableConfig}: plain, inspectable, JSON-serializable
 * data rather than opaque closures, and a {@see \Flowd\Phirewall\ConfigLayer}.
 * Apply one (or several) onto your own cache with
 * {@see \Flowd\Phirewall\Config::with()}; presets never receive a cache
 * themselves, keeping shareable rule data decoupled from the stateful counter
 * store:
 *
 * ```php
 * // A preset on its own:
 * $config = (new Config($cache))->with(Presets::scannerBlocking());
 *
 * // A preset layered with your own portable rules (later args win by name):
 * $config = (new Config($cache))->with(Presets::scannerBlocking(), $myPortable);
 *
 * // Several presets stacked together:
 * $config = (new Config($cache))->with(
 *     Presets::scannerBlocking(),
 *     Presets::sensitivePathBlocking(),
 * );
 * ```
 *
 * Every rule is namespaced under a `preset.<area>.*` name so a later layer that
 * redefines the rule by name overrides it predictably, and every accessor
 * returns a FRESH instance: the presets themselves are immutable and stateless.
 *
 * The shipped presets target signals that are universal across applications
 * (scanner User-Agents, missing browser headers, well-known sensitive paths),
 * so they assume nothing about your routing. A `PortableConfig` you build
 * yourself can key on whatever fits your deployment, including routes your own
 * apps standardize.
 *
 * ## Versioning
 *
 * {@see VERSION} identifies the bundled rule catalogue and is bumped whenever a
 * preset's rule set changes in a way integrators should review. Phirewall ships
 * no update-check mechanism and performs no network I/O: to surface "a newer
 * ruleset is available", compare {@see VERSION} against a feed you trust
 * (Packagist, an internal config service, a versioned JSON document) with
 * {@see version_compare()}, e.g.
 * `version_compare(Presets::VERSION, $latestFromYourFeed, '<')`.
 */
final class Presets
{
    /**
     * Version of the bundled preset catalogue. Bumped whenever a preset's rule
     * set changes in a way integrators should review. Compare it against a feed
     * you trust with {@see version_compare()} to surface "a newer ruleset is
     * available" (see the class docblock).
     */
    public const VERSION = '1.0.0';

    public const SCANNER_BLOCKING = 'scanner-blocking';

    public const SENSITIVE_PATH_BLOCKING = 'sensitive-path-blocking';

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
            self::SCANNER_BLOCKING,
            self::SENSITIVE_PATH_BLOCKING,
        ];
    }

    // ── Scanner blocking ─────────────────────────────────────────────────

    /**
     * Block automated attack tooling.
     *
     *  - `preset.scanner.known-tools`: blocks requests whose User-Agent matches
     *    a known scanner / exploit tool (sqlmap, nikto, nmap, nuclei, ...).
     *  - `preset.scanner.suspicious-headers`: blocks requests missing the
     *    standard browser `Accept` / `Accept-Language` / `Accept-Encoding`
     *    headers.
     *
     * Note: the suspicious-headers rule is the more aggressive of the two; some
     * legitimate API clients, privacy tools, and embedded browsers omit those
     * headers. If your traffic includes non-browser clients, override or drop
     * `preset.scanner.suspicious-headers` by name when combining.
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
     * application serves `/.git/...`, `/.env`, `/.aws/credentials`, or `/.htpasswd`.
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
            self::SCANNER_BLOCKING => self::scannerBlocking(),
            self::SENSITIVE_PATH_BLOCKING => self::sensitivePathBlocking(),
            default => throw new \InvalidArgumentException(sprintf('Unknown preset "%s".', $preset)),
        };
    }
}
