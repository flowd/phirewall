<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;

/**
 * The first block captured while evaluating allow2ban rules.
 *
 * Allow2BanEvaluator deliberately keeps looping after it has decided to block so
 * that each rule whose key is not already banned still increments its hit counter
 * (unlike Fail2BanEvaluator, which early-returns on its first decision). It therefore
 * needs to remember the first blocking decision and apply it once the loop is done,
 * carrying the decision path, rule name, and result together as a typed value.
 */
final readonly class Allow2BanDecision
{
    public function __construct(
        public DecisionPath $decisionPath,
        public string $rule,
        public FirewallResult $result,
    ) {
    }
}
