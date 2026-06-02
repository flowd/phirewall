<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Flowd\Phirewall\Owasp\CoreRule;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Per-request memo for collected variable values.
 *
 * A single request is typically evaluated against many CRS rules, and several of
 * those rules target the same variable (e.g. ARGS or REQUEST_HEADERS). Deriving the
 * same request data once per rule re-runs getQueryParams()/getParsedBody(), re-flattens
 * headers and re-concatenates the URI N times. This memo collects each DISTINCT variable
 * exactly once per request — keyed by variable name — and shares the result across rules.
 *
 * Collected values per variable are capped at {@see CoreRule::MAX_VALUES} to bound the
 * cost of attacker-controlled, count-unbounded variables (e.g. ARGS with thousands of
 * parameters), mirroring ModSecurity's SecArgumentsLimit.
 */
final class RequestVariableValues
{
    /**
     * Collected values cache keyed by variable name.
     *
     * @var array<string, list<string>>
     */
    private array $valuesByVariableName = [];

    public function __construct(
        private readonly ServerRequestInterface $serverRequest,
    ) {
    }

    /**
     * Return the collected values for the given variable name, collecting them once and
     * caching the result for subsequent rules. Unknown variable names yield an empty list.
     *
     * @return list<string>
     */
    public function valuesFor(string $variableName): array
    {
        if (isset($this->valuesByVariableName[$variableName])) {
            return $this->valuesByVariableName[$variableName];
        }

        $collector = VariableCollectorFactory::create($variableName);
        if (!$collector instanceof VariableCollectorInterface) {
            return $this->valuesByVariableName[$variableName] = [];
        }

        $collected = $collector->collect($this->serverRequest);
        if (count($collected) > CoreRule::MAX_VALUES) {
            $collected = array_slice($collected, 0, CoreRule::MAX_VALUES);
        }

        return $this->valuesByVariableName[$variableName] = $collected;
    }
}
