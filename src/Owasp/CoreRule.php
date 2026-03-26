<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

use Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorFactory;
use Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorInterface;
use Flowd\Phirewall\Owasp\Variable\VariableCollectorFactory;
use Flowd\Phirewall\Owasp\Variable\VariableCollectorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Minimal representation of a single OWASP CRS rule.
 * This is a pragmatic subset that supports common patterns (REQUEST_URI + @rx) and a few additional operators/variables.
 *
 * Variable collection is delegated to VariableCollectorInterface implementations.
 * Operator evaluation is delegated to OperatorEvaluatorInterface implementations.
 */
final readonly class CoreRule
{
    /** @var list<VariableCollectorInterface> Resolved variable collectors for this rule. */
    private array $variableCollectors;

    /** Resolved operator evaluator for this rule. */
    private OperatorEvaluatorInterface $operatorEvaluator;

    /**
     * @param list<string> $variables
     * @param array<string, int|string|bool> $actions
     */
    public function __construct(
        public int $id,
        public array $variables, // list of variable identifiers (e.g., ['REQUEST_URI'])
        public string $operator, // e.g., '@rx', '@contains'
        public string $operatorArgument, // e.g., pattern for @rx or needle for @contains
        public array $actions, // parsed action map (e.g., ['phase' => '2', 'deny' => true, 'msg' => '...'])
        public ?string $contextFolder = null, // folder path for context (e.g., for @pmFromFile)
    ) {
        $this->variableCollectors = VariableCollectorFactory::createCollectors($this->variables);
        $this->operatorEvaluator = OperatorEvaluatorFactory::create(
            $this->operator,
            $this->operatorArgument,
            $this->contextFolder,
        );
    }

    public function matches(ServerRequestInterface $serverRequest): bool
    {
        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return false;
        }

        $values = $this->collectVariableValues($serverRequest);
        if ($values === []) {
            return false;
        }

        return $this->operatorEvaluator->evaluate($values);
    }

    /**
     * Collect target values from the request using all resolved variable collectors.
     *
     * @return list<string>
     */
    private function collectVariableValues(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];
        foreach ($this->variableCollectors as $variableCollector) {
            array_push($collected, ...$variableCollector->collect($serverRequest));
        }

        return array_values(array_filter($collected, fn(string $item): bool => $item !== ''));
    }
}
