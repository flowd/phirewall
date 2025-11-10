<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Closure;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ClosureRequestMatcher implements RequestMatcherInterface
{
    /**
     * @param Closure(ServerRequestInterface):bool $callback
     */
    public function __construct(private Closure $callback)
    {
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $cb = $this->callback;
        return $cb($serverRequest) ? MatchResult::matched('custom') : MatchResult::noMatch();
    }
}
