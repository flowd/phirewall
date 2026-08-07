<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

/**
 * Capability that a {@see \Flowd\Phirewall\Config\RequestMatcherInterface} can add
 * when a match-time error forces a fail-open / fail-closed decision.
 *
 * The {@see \Flowd\Phirewall\Http\Firewall} hands the evaluating Config's
 * {@see \Flowd\Phirewall\Config::isFailOpen()} policy to every aware matcher at
 * construction, mirroring {@see CompiledDataCacheAware}. A matcher that is never
 * injected keeps the fail-open default, matching the Config default.
 */
interface FailOpenAware
{
    /**
     * Receive the evaluating Config's failure policy. Called before any match;
     * implementations should treat repeated calls as idempotent.
     */
    public function useFailOpen(bool $failOpen): void;
}
