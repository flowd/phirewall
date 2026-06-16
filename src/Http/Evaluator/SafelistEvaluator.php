<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates safelist rules: returns a safelisted result on the first match.
 */
final readonly class SafelistEvaluator implements EvaluatorInterface
{
    use ResolvesClientIpForMatchers;

    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $defaultIpResolver = $evaluationContext->config->clientIpResolver();

        foreach ($evaluationContext->config->safelists->rules() as $safelistRule) {
            $name = $safelistRule->name();
            $match = $this->matchWithClientIpResolver($safelistRule->matcher(), $serverRequest, $defaultIpResolver);
            if ($match->isMatch()) {
                $evaluationContext->dispatch(new SafelistMatched($name, $serverRequest));

                $evaluationContext->decisionPath = DecisionPath::Safelisted;
                $evaluationContext->decisionRule = $name;

                $headers = $evaluationContext->responseHeadersEnabled
                    ? ['X-Phirewall-Safelist' => $name]
                    : [];

                return FirewallResult::safelisted($name, $headers);
            }
        }

        return null;
    }
}
