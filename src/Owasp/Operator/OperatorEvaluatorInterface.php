<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates an OWASP CRS operator against a list of collected variable values.
 */
interface OperatorEvaluatorInterface
{
    /**
     * Evaluate the operator against the given values. Returns true if any value matches.
     *
     * @param list<string> $values
     */
    public function evaluate(array $values): bool;
}
