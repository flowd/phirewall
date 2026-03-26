<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header values from the request.
 */
final readonly class RequestHeadersCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        foreach ($serverRequest->getHeaders() as $values) {
            foreach ($values as $value) {
                $collected[] = (string) $value;
            }
        }

        return $collected;
    }
}
