<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Psr\Http\Message\ServerRequestInterface;

/**
 * A typed matcher for inspecting a request and returning a rich MatchResult.
 */
interface RequestMatcherInterface
{
    public function match(ServerRequestInterface $serverRequest): MatchResult;
}
