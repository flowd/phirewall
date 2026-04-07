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
 * Includes OWASP diagnostics header when enabled and the match source is 'owasp'.
 */
final readonly class BlocklistEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        foreach ($evaluationContext->config->blocklists->rules() as $blocklistRule) {
            $name = $blocklistRule->name();
            $match = $blocklistRule->matcher()->match($serverRequest);
            if ($match->isMatch()) {
                $evaluationContext->dispatch(new BlocklistMatched($name, $serverRequest));

                $headers = $evaluationContext->responseHeaders('blocklist', $name);
                if ($evaluationContext->owaspDiagnosticsHeaderEnabled && $match->source() === 'owasp') {
                    $meta = $match->metadata();
                    if (isset($meta['owasp_rule_id'])) {
                        $headers['X-Phirewall-Owasp-Rule'] = (string) $meta['owasp_rule_id'];
                    }
                }

                $evaluationContext->decisionPath = DecisionPath::Blocklisted;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'blocklist', $headers);
            }
        }

        return null;
    }
}
