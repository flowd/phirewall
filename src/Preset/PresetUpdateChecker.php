<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Preset;

/**
 * Contract for checking whether a bundled {@see Presets} ruleset has a newer
 * version available somewhere the integrator controls.
 *
 * Phirewall intentionally ships no concrete network-bound implementation: the
 * library never hardcodes a remote endpoint nor performs I/O on your behalf.
 * Wiring an actual source — a Packagist release feed, a versioned JSON document
 * behind an HTTPS URL, an internal config service, etc. — is the integrator's
 * job. Implement this interface against whatever source you trust and inject it
 * where you build your Config; the {@see NullPresetUpdateChecker} is the safe
 * default when no such source is wired.
 *
 * Implementations MUST treat the preset name as an opaque identifier (the
 * `Presets::*` name constants) and SHOULD be side-effect free beyond the lookup
 * they perform.
 */
interface PresetUpdateChecker
{
    /**
     * Return the latest known version string for the given preset, or null when
     * the source has no information about it (unknown preset, lookup failed,
     * offline, …). Callers should treat null as "cannot determine — assume
     * current".
     *
     * @param string $preset One of the {@see Presets} name constants.
     */
    public function latestVersion(string $preset): ?string;

    /**
     * Whether the given preset version is behind the latest known version.
     *
     * Implementations decide the comparison strategy (typically
     * {@see version_compare()} against {@see latestVersion()}). They MUST return
     * false when the latest version cannot be determined, so an unreachable
     * source never reports a false "outdated" signal.
     *
     * @param string $preset One of the {@see Presets} name constants.
     * @param string $currentVersion The version currently in use, e.g. {@see Presets::VERSION}.
     */
    public function isOutdated(string $preset, string $currentVersion): bool;
}
