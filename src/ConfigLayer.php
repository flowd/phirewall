<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

/**
 * A layer that can be applied onto a {@see Config} via {@see Config::with()}.
 *
 * Both a live {@see Config} and a {@see Portable\PortableConfig} are layers, so
 * presets and config sources compose uniformly regardless of how they are built:
 *
 * ```php
 * $config = (new Config($cache))->with($aPreset, $aPortableConfig, $anotherConfig);
 * ```
 */
interface ConfigLayer
{
    /**
     * Overlay this layer onto $base and return a NEW Config, leaving $base
     * unchanged. This layer wins on a rule-name clash (later layers win).
     */
    public function applyTo(Config $config): Config;
}
