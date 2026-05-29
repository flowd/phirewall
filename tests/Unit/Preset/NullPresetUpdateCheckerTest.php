<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Preset;

use Flowd\Phirewall\Preset\NullPresetUpdateChecker;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Preset\PresetUpdateChecker;
use PHPUnit\Framework\TestCase;

final class NullPresetUpdateCheckerTest extends TestCase
{
    public function testImplementsTheCheckerContract(): void
    {
        $this->assertInstanceOf(PresetUpdateChecker::class, new NullPresetUpdateChecker());
    }

    public function testLatestVersionIsAlwaysNull(): void
    {
        $checker = new NullPresetUpdateChecker();
        $this->assertNull($checker->latestVersion(Presets::API_RATE_LIMITING));
        $this->assertNull($checker->latestVersion('anything-at-all'));
    }

    public function testNeverReportsOutdated(): void
    {
        $checker = new NullPresetUpdateChecker();
        $this->assertFalse($checker->isOutdated(Presets::API_RATE_LIMITING, Presets::VERSION));
        // Even a deliberately ancient version is reported as current — the null
        // checker has no source to compare against.
        $this->assertFalse($checker->isOutdated(Presets::LOGIN_PROTECTION, '0.0.1'));
    }
}
