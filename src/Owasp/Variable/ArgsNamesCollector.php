<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects argument names (keys) from both query parameters and parsed body.
 */
final readonly class ArgsNamesCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        $queryParams = $serverRequest->getQueryParams();
        foreach (array_keys($queryParams) as $key) {
            $collected[] = (string) $key;
        }

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            foreach (array_keys($parsed) as $key) {
                $collected[] = (string) $key;
            }
        }

        return $collected;
    }
}
