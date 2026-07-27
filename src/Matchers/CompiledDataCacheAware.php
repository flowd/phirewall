<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Support\CompiledDataCache;

/**
 * Capability that a {@see \Flowd\Phirewall\Config\RequestMatcherInterface} can add
 * when it builds expensive data lazily and wants the evaluating Config's
 * compiled-data cache.
 *
 * The {@see \Flowd\Phirewall\Http\Firewall} hands the cache of
 * {@see \Flowd\Phirewall\Config::compiledDataCache()} to every aware matcher,
 * filter, and throttle scope at construction, mirroring how
 * {@see ClientIpResolverAware} late-binds the IP resolver. A Config without a
 * compiled-data cache injects nothing; the matcher then builds its data
 * directly.
 */
interface CompiledDataCacheAware
{
    /**
     * Receive the evaluating Config's compiled-data cache. Called before any
     * match; implementations should treat repeated calls as idempotent.
     */
    public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void;
}
