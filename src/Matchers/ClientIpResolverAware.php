<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Capability that a {@see \Flowd\Phirewall\Config\RequestMatcherInterface} can add
 * when it resolves the client IP and can late-bind its resolver.
 *
 * When such a matcher is constructed without an explicit IP resolver it does not
 * decide how to read the client IP until it runs: the evaluating {@see \Flowd\Phirewall\Config}
 * supplies its resolver via {@see matchWithResolver()}, the same way keyless counter
 * rules resolve their key through {@see \Flowd\Phirewall\Config::resolveKey()}. A matcher
 * given an explicit resolver at construction ignores the supplied default and keeps its own.
 */
interface ClientIpResolverAware
{
    /**
     * Match using this matcher's explicit IP resolver if one was set at
     * construction, otherwise using $defaultResolver (the evaluating Config's
     * resolver).
     *
     * @param callable(ServerRequestInterface): ?string $defaultResolver
     */
    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult;
}
