<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Passive tracking evaluator: increments counters and dispatches TrackHit events.
 *
 * Never blocks a request (always returns null).
 */
final readonly class TrackEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        foreach ($evaluationContext->config->tracks->rules() as $trackRule) {
            $name = $trackRule->name();
            if ($trackRule->filter()->match($serverRequest)->isMatch()) {
                $key = $trackRule->keyExtractor()->extract($serverRequest);
                if ($key !== null) {
                    $normalizedKey = ($evaluationContext->normalize)((string) $key);
                    $counterKey = $evaluationContext->config->cacheKeyGenerator()->trackKey($name, $normalizedKey);
                    $count = $evaluationContext->counter->increment($counterKey, $trackRule->period())->count;

                    $evaluationContext->dispatch(new TrackHit(
                        rule: $name,
                        key: $normalizedKey,
                        period: $trackRule->period(),
                        count: $count,
                        serverRequest: $serverRequest,
                        limit: $trackRule->limit(),
                    ));
                }
            }
        }

        return null;
    }
}
