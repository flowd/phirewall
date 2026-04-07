<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Factory that creates the appropriate operator evaluator based on the operator name.
 */
final class OperatorEvaluatorFactory
{
    public static function create(
        string $operator,
        string $operatorArgument,
        ?string $contextFolder = null,
    ): OperatorEvaluatorInterface {
        return match (strtolower($operator)) {
            '@rx' => new RegexEvaluator($operatorArgument),
            '@contains' => new ContainsEvaluator($operatorArgument),
            '@streq' => new StringEqualEvaluator($operatorArgument),
            '@startswith', '@beginswith' => new StartsWithEvaluator($operatorArgument),
            '@endswith' => new EndsWithEvaluator($operatorArgument),
            '@pm' => new PhraseMatchEvaluator($operatorArgument),
            '@pmfromfile' => new PhraseMatchFromFileEvaluator($operatorArgument, $contextFolder),
            default => new UnsupportedOperatorEvaluator(),
        };
    }
}
