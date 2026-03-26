<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values for case-insensitive string equality (@streq operator).
 */
final readonly class StringEqualEvaluator implements OperatorEvaluatorInterface
{
    public function __construct(private string $expected)
    {
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        foreach ($values as $value) {
            if (strcasecmp($value, $this->expected) === 0) {
                return true;
            }
        }

        return false;
    }
}
