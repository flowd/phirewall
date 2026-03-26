<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values for case-insensitive prefix match (@startswith / @beginswith operators).
 */
final readonly class StartsWithEvaluator implements OperatorEvaluatorInterface
{
    private int $prefixLength;

    public function __construct(private string $prefix)
    {
        $this->prefixLength = strlen($this->prefix);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        if ($this->prefix === '') {
            return false;
        }

        foreach ($values as $value) {
            if (strncasecmp($value, $this->prefix, $this->prefixLength) === 0) {
                return true;
            }
        }

        return false;
    }
}
