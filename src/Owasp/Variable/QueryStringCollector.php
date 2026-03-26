<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the raw query string from the request URI.
 */
final readonly class QueryStringCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        return [$serverRequest->getUri()->getQuery()];
    }
}
