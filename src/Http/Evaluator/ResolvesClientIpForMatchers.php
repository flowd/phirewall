<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\ClientIpResolverAware;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Shared matcher invocation that late-binds the client-IP resolver.
 *
 * A {@see ClientIpResolverAware} matcher (IP-aware) with no explicit resolver reads
 * the client IP through $defaultResolver - the evaluating Config's resolver
 * ({@see \Flowd\Phirewall\Config::clientIpResolver()}) - so IP rules honour the
 * Config they run under regardless of which layer or rule section defined them. Any
 * other matcher is matched directly.
 */
trait ResolvesClientIpForMatchers
{
    /**
     * @param callable(ServerRequestInterface): ?string $defaultResolver
     */
    private function matchWithClientIpResolver(
        RequestMatcherInterface $requestMatcher,
        ServerRequestInterface $serverRequest,
        callable $defaultResolver,
    ): MatchResult {
        return $requestMatcher instanceof ClientIpResolverAware
            ? $requestMatcher->matchWithResolver($serverRequest, $defaultResolver)
            : $requestMatcher->match($serverRequest);
    }
}
