<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all argument values and names from both query parameters and parsed body.
 */
final readonly class ArgsCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        $queryParams = $serverRequest->getQueryParams();
        foreach ($queryParams as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $nestedValue) {
                    if (is_scalar($nestedValue)) {
                        $collected[] = (string) $nestedValue;
                    }
                }
            } elseif (is_scalar($value)) {
                $collected[] = (string) $value;
            }

            $collected[] = (string) $key; // include argument names for name-based checks
        }

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            foreach ($parsed as $key => $value) {
                if (is_array($value)) {
                    foreach ($value as $nestedValue) {
                        if (is_scalar($nestedValue)) {
                            $collected[] = (string) $nestedValue;
                        }
                    }
                } elseif (is_scalar($value)) {
                    $collected[] = (string) $value;
                }

                $collected[] = (string) $key;
            }
        }

        return $collected;
    }
}
