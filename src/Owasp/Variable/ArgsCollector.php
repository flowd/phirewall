<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all argument values and names from both query parameters and parsed body.
 *
 * Collection works from the already-parsed PSR-7 arrays (getQueryParams()/getParsedBody()),
 * so the number of entries is bounded by the runtime's own input parsing (e.g. PHP's
 * `max_input_vars` and `max_input_nesting_level`). Nested parameters (`a[b][c]=x`) are flattened
 * to every scalar leaf value and key so a payload cannot evade an ARGS rule by nesting. The
 * per-variable evaluation cap — and the fail-closed behaviour when it is exceeded — is applied
 * centrally by {@see RequestVariableValues}, so this collector does not truncate: truncating here
 * would drop a parameter's name while keeping its value (a half-collected parameter) and hide the
 * overflow from the fail-closed check.
 */
final readonly class ArgsCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        $this->collectFrom($serverRequest->getQueryParams(), $collected);

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            $this->collectFrom($parsed, $collected);
        }

        return $collected;
    }

    /**
     * Append values and names from a parameter map.
     *
     * @param array<array-key, mixed> $parameters
     * @param list<string> $collected
     */
    private function collectFrom(array $parameters, array &$collected): void
    {
        foreach ($parameters as $key => $value) {
            if (is_array($value)) {
                $this->collectFrom($value, $collected);
            } elseif (is_scalar($value)) {
                $collected[] = (string) $value;
            }

            $collected[] = (string) $key; // include argument names at every level for name-based checks
        }
    }
}
