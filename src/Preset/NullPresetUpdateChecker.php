<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Preset;

/**
 * Default {@see PresetUpdateChecker} that never reports an update and performs
 * no I/O.
 *
 * This is the safe out-of-the-box wiring: presets are treated as current until
 * the integrator injects a real checker backed by a source they trust (see
 * {@see PresetUpdateChecker}). Using it keeps update-awareness optional without
 * coupling the firewall to any network call.
 */
final class NullPresetUpdateChecker implements PresetUpdateChecker
{
    public function latestVersion(string $preset): ?string
    {
        return null;
    }

    public function isOutdated(string $preset, string $currentVersion): bool
    {
        return false;
    }
}
