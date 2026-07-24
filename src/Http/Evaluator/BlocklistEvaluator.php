<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates blocklist rules: returns a blocked result on the first match.
 *
 * Copies matcher-provided diagnostic headers onto the blocked response when
 * enabled ({@see EvaluationContext::diagnosticHeaders()}).
 */
final readonly class BlocklistEvaluator implements EvaluatorInterface
{
    use ResolvesClientIpForMatchers;

    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $defaultIpResolver = $evaluationContext->config->clientIpResolver();

        foreach ($evaluationContext->config->blocklists->rules() as $blocklistRule) {
            $name = $blocklistRule->name();
            $match = $this->matchWithClientIpResolver($blocklistRule->matcher(), $serverRequest, $defaultIpResolver);
            if ($match->isMatch()) {
                $evaluationContext->dispatch(new BlocklistMatched($name, $serverRequest));

                $headers = [
                    ...$evaluationContext->diagnosticHeaders($match),
                    ...$evaluationContext->responseHeaders('blocklist', $name),
                ];

                $evaluationContext->decisionPath = DecisionPath::Blocklisted;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'blocklist', $headers);
            }
        }

        return null;
    }
}
