<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

use Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorFactory;
use Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorInterface;
use Flowd\Phirewall\Owasp\Variable\RequestVariableValues;
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
        $this->operatorEvaluator = OperatorEvaluatorFactory::create(
            $this->operator,
            $this->operatorArgument,
            $this->contextFolder,
        );
    }

    /**
     * Evaluate the rule against the request.
     *
     * When evaluating many rules for the same request, pass a shared {@see RequestVariableValues}
     * memo so each distinct variable is collected only once across all rules.
     */
    public function matches(ServerRequestInterface $serverRequest, ?RequestVariableValues $requestVariableValues = null): bool
    {
        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return false;
        }

        $requestVariableValues ??= new RequestVariableValues($serverRequest);

        $values = $this->collectVariableValues($requestVariableValues);

        // Fail closed: if a variable this rule inspects was truncated at the per-variable
        // cap, the dropped portion is un-inspectable, so treat the oversized request as a
        // match rather than letting a payload padded past the cap slip through unevaluated.
        foreach ($this->variables as $variable) {
            if ($requestVariableValues->wasCapped($variable)) {
                return true;
            }
        }

        if ($values === []) {
            return false;
        }

        return $this->operatorEvaluator->evaluate($values);
    }

    /**
     * Assemble this rule's target values from the shared per-request memo.
     *
     * Empty values are dropped. Each targeted variable's values are independently
     * capped by {@see RequestVariableValues::valuesFor()}; there is deliberately NO
     * aggregate cap across variables here, so a high-volume earlier variable cannot
     * short-circuit evaluation of a later one. A variable truncated at its cap is
     * surfaced via {@see RequestVariableValues::wasCapped()} and handled (fail-closed)
     * in {@see matches()}, not here.
     *
     * @return list<string>
     */
    private function collectVariableValues(RequestVariableValues $requestVariableValues): array
    {
        /** @var list<string> $collected */
        $collected = [];
        foreach ($this->variables as $variable) {
            foreach ($requestVariableValues->valuesFor($variable) as $value) {
                if ($value !== '') {
                    $collected[] = $value;
                }
            }
        }

        return $collected;
    }
}
