<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all argument values and names from both query parameters and parsed body.
 *
 * Collection works from the already-parsed PSR-7 arrays (getQueryParams()/getParsedBody()),
 * so the number of entries is bounded by the runtime's own input parsing (e.g. PHP's
 * `max_input_vars` and `max_input_nesting_level`). PHP expands a bracketed parameter name like
 * `a[b][c]=x` into a nested array; this collector flattens it back to the leaf value (`x`) and the
 * original bracketed name (`a[b][c]`), so a payload cannot evade an ARGS rule by nesting and the
 * collected name matches the request parameter rather than each path segment. The per-variable
 * evaluation cap — and the fail-closed behaviour when it is exceeded — is applied centrally by
 * {@see RequestVariableValues}, so this collector does not truncate: truncating here would drop a
 * parameter's name while keeping its value (a half-collected parameter) and hide the overflow from
 * the fail-closed check.
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
     * Append every scalar leaf value and its flattened bracketed name from a parameter map.
     *
     * @param array<array-key, mixed> $parameters
     * @param list<string> $collected
     * @param string $namePrefix Bracketed name accumulated while descending (e.g. "foo[bar]")
     */
    private function collectFrom(array $parameters, array &$collected, string $namePrefix = ''): void
    {
        foreach ($parameters as $key => $value) {
            // Rebuild the bracketed parameter name as PHP parsed it (foo[bar]; list items such as
            // foo[]=a get numeric indices, e.g. foo[0]) so name-based rules see the parameter name
            // rather than each path segment.
            $name = $namePrefix === '' ? (string) $key : $namePrefix . '[' . $key . ']';

            if (is_array($value)) {
                $this->collectFrom($value, $collected, $name);
                continue;
            }

            if (is_scalar($value)) {
                $collected[] = (string) $value;
            }

            $collected[] = $name;
        }
    }
}
