<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values for case-insensitive suffix match (@endswith operator).
 */
final readonly class EndsWithEvaluator implements OperatorEvaluatorInterface
{
    private int $suffixLength;

    public function __construct(private string $suffix)
    {
        $this->suffixLength = strlen($this->suffix);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        if ($this->suffix === '' || $this->suffixLength === 0) {
            return false;
        }

        foreach ($values as $value) {
            if (strcasecmp(substr($value, -$this->suffixLength), $this->suffix) === 0) {
                return true;
            }
        }

        return false;
    }
}
