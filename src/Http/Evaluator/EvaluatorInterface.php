<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A single stage in the firewall evaluation pipeline.
 *
 * Implementations inspect the request and optionally return a FirewallResult
 * to short-circuit the pipeline. Returning null continues to the next evaluator.
 */
interface EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult;
}
