<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values for case-insensitive substring match (@contains operator).
 */
final readonly class ContainsEvaluator implements OperatorEvaluatorInterface
{
    public function __construct(private string $needle)
    {
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        if ($this->needle === '') {
            return false;
        }

        foreach ($values as $value) {
            if (stripos($value, $this->needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
