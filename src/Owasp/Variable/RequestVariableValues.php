<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

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
 * Collected values per variable are capped at {@see $maxValuesPerCrsVariable} (default
 * {@see self::defaultMaxValuesPerCrsVariable()}) to bound the per-request evaluation cost of
 * attacker-controlled, count-unbounded variables (e.g. ARGS with thousands of parameters).
 * The cap is per variable, not aggregate, so padding one variable cannot short-circuit
 * evaluation of a rule that targets another. When a variable IS truncated, {@see wasCapped()}
 * reports it so callers can fail closed rather than silently evaluating a partial value set —
 * silent truncation would otherwise let an attacker push a payload past the cap to evade a
 * rule targeting that same variable.
 */
final class RequestVariableValues
{
    /**
     * Fallback per-variable value cap (= 2 × the conventional `max_input_vars` default of
     * 1000), used when PHP's `max_input_vars` is unavailable or non-positive.
     */
    public const DEFAULT_MAX_VALUES_PER_CRS_VARIABLE = 2000;

    /**
     * Collected values cache keyed by variable name.
     *
     * @var array<string, list<string>>
     */
    private array $valuesByVariableName = [];

    /**
     * Names of variables whose collected values were truncated at the cap this request.
     *
     * @var array<string, true>
     */
    private array $cappedVariables = [];

    private readonly int $maxValuesPerCrsVariable;

    /**
     * @throws \InvalidArgumentException When an explicit $maxValuesPerCrsVariable is not a positive
     *                                   integer. A non-positive cap would truncate every collected variable to (at most) nothing
     *                                   and mark it capped, making every deny rule fail closed — i.e. silently block all traffic.
     */
    public function __construct(
        private readonly ServerRequestInterface $serverRequest,
        ?int $maxValuesPerCrsVariable = null,
    ) {
        if ($maxValuesPerCrsVariable !== null && $maxValuesPerCrsVariable < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxValuesPerCrsVariable must be a positive integer, %d given.', $maxValuesPerCrsVariable),
            );
        }

        $this->maxValuesPerCrsVariable = $maxValuesPerCrsVariable ?? self::defaultMaxValuesPerCrsVariable();
    }

    /**
     * Default per-variable value cap: twice PHP's `max_input_vars` directive. The cap counts
     * collected values, and variables such as ARGS emit both a name and a value per parameter
     * (~2 values per input var), so doubling max_input_vars sizes the budget to the parameter
     * count the runtime actually accepts — a request PHP can fully parse is never falsely
     * truncated (and thus never falsely fails closed). Falls back to
     * {@see self::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE} when the directive is unset or non-positive
     * (e.g. `-1` / "unlimited"), where the firewall deliberately imposes its own floor rather
     * than inherit an unbounded budget that would defeat the DoS protection.
     */
    public static function defaultMaxValuesPerCrsVariable(): int
    {
        $configured = (int) ini_get('max_input_vars');

        return $configured > 0 ? $configured * 2 : self::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE;
    }

    /**
     * The effective per-variable value cap in force for this request.
     */
    public function maxValuesPerCrsVariable(): int
    {
        return $this->maxValuesPerCrsVariable;
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
        if (count($collected) > $this->maxValuesPerCrsVariable) {
            $collected = array_slice($collected, 0, $this->maxValuesPerCrsVariable);
            $this->cappedVariables[$variableName] = true;
        }

        return $this->valuesByVariableName[$variableName] = $collected;
    }

    /**
     * Whether the named variable's values were truncated at the per-variable cap on this
     * request. Only meaningful once {@see valuesFor()} has been called for the variable —
     * callers that have collected the variable fail closed on a true result instead of
     * evaluating a partially-inspected value set.
     */
    public function wasCapped(string $variableName): bool
    {
        return isset($this->cappedVariables[$variableName]);
    }
}
