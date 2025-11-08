<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Psr\Http\Message\ServerRequestInterface;

/**
 * A typed matcher for inspecting a request and deciding if it matches.
 */
interface RequestMatcherInterface
{
    public function matches(ServerRequestInterface $serverRequest): bool;
}
