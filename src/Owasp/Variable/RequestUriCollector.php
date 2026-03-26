<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the full request URI (path + optional query string).
 */
final readonly class RequestUriCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $uri = $serverRequest->getUri();
        $query = $uri->getQuery();
        $value = $uri->getPath() . ($query !== '' ? '?' . $query : '');

        return [$value];
    }
}
