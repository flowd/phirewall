<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

use Flowd\Phirewall\Owasp\Variable\RequestVariableValues;
use Psr\Http\Message\ServerRequestInterface;

/**
 * CoreRuleSet stores parsed CRS rules and allows enabling/disabling by id.
 */
final class CoreRuleSet
{
    /** @var array<int, CoreRule> */
    private array $rulesById = [];

    /** @var array<int, bool> */
    private array $enabled = [];

    /**
     * @param iterable<CoreRule> $rules
     * @param int|null $maxValuesPerCrsVariable Per-variable value cap applied while evaluating a
     *                                          request; null (default) derives it from PHP's `max_input_vars`
     *                                          (see {@see RequestVariableValues::defaultMaxValuesPerCrsVariable()}).
     *
     * @throws \InvalidArgumentException When an explicit $maxValuesPerCrsVariable is not positive
     *                                   (a non-positive cap fails every deny rule closed, silently blocking all traffic).
     */
    public function __construct(iterable $rules = [], private readonly ?int $maxValuesPerCrsVariable = null)
    {
        if ($maxValuesPerCrsVariable !== null && $maxValuesPerCrsVariable < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxValuesPerCrsVariable must be a positive integer, %d given.', $maxValuesPerCrsVariable),
            );
        }

        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    /**
     * Get a rule by ID.
     */
    public function getRule(int $id): ?CoreRule
    {
        return $this->rulesById[$id] ?? null;
    }

    public function add(CoreRule $coreRule): void
    {
        $this->rulesById[$coreRule->id] = $coreRule;
        $this->enabled[$coreRule->id] = true; // default: enabled
    }

    public function enable(int $id): void
    {
        if (isset($this->rulesById[$id])) {
            $this->enabled[$id] = true;
        }
    }

    public function disable(int $id): void
    {
        if (isset($this->rulesById[$id])) {
            $this->enabled[$id] = false;
        }
    }

    public function isEnabled(int $id): bool
    {
        return $this->enabled[$id] ?? false;
    }

    /**
     * Evaluate the request against all enabled rules. Returns the first matched rule id or null.
     */
    public function match(ServerRequestInterface $serverRequest): ?int
    {
        // Collect each distinct variable once and share it across every rule for this request.
        $requestVariableValues = new RequestVariableValues($serverRequest, $this->maxValuesPerCrsVariable);

        foreach ($this->rulesById as $id => $rule) {
            if (($this->enabled[$id] ?? false) === false) {
                continue;
            }

            if ($rule->matches($serverRequest, $requestVariableValues)) {
                return $rule->id;
            }
        }

        return null;
    }

    /**
     * @return list<int>
     */
    public function ids(): array
    {
        return array_keys($this->rulesById);
    }
}
