<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Throttle\FixedWindowCounter;
use Flowd\Phirewall\Throttle\SlidingWindowStrategy;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates throttle rules: blocks when rate limit is exceeded, captures
 * pending rate-limit headers for pass-through responses.
 *
 * Retry-After is always included regardless of responseHeadersEnabled.
 * X-Phirewall headers are only included when responseHeadersEnabled is true.
 */
final class ThrottleEvaluator implements EvaluatorInterface
{
    private ?FixedWindowCounter $fixedWindowCounter = null;

    private ?SlidingWindowStrategy $slidingStrategy = null;

    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        foreach ($evaluationContext->config->throttles->rules() as $throttleRule) {
            $name = $throttleRule->name();
            $key = $throttleRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedKey = ($evaluationContext->normalize)((string) $key);
            $limit = $throttleRule->resolveLimit($serverRequest);
            $period = $throttleRule->resolvePeriod($serverRequest);

            // When period is dynamic, include the resolved period in the cache key so
            // different periods for the same discriminator get independent counters.
            $effectiveRuleName = $throttleRule->hasDynamicPeriod()
                ? $name . ':p' . $period
                : $name;

            if ($throttleRule->isSliding()) {
                $throttleIncrement = $this->slidingStrategy($evaluationContext)
                    ->increment($effectiveRuleName, $normalizedKey, $period);
                // ceil() rounds up the floating-point sliding window estimate for a conservative safety margin
                $count = (int) ceil($throttleIncrement->count);
                $retryAfter = $throttleIncrement->retryAfter;
            } else {
                $counterKey = $evaluationContext->config->cacheKeyGenerator()
                    ->throttleKey($effectiveRuleName, $normalizedKey);
                $fixedWindowResult = $this->fixedWindowCounter($evaluationContext)
                    ->increment($counterKey, $period);
                $count = $fixedWindowResult->count;
                $retryAfter = $fixedWindowResult->retryAfter;
            }

            $remaining = max(0, $limit - $count);

            if ($count > $limit) {
                $evaluationContext->dispatch(new ThrottleExceeded(
                    rule: $name,
                    key: $normalizedKey,
                    limit: $limit,
                    period: $period,
                    count: $count,
                    retryAfter: $retryAfter,
                    serverRequest: $serverRequest,
                ));

                $headers = ['Retry-After' => (string) max(1, $retryAfter)]
                    + $evaluationContext->responseHeaders('throttle', $name);
                if ($evaluationContext->rateLimitHeadersEnabled) {
                    $headers += [
                        'X-RateLimit-Limit' => (string) $limit,
                        'X-RateLimit-Remaining' => '0',
                        'X-RateLimit-Reset' => (string) max(1, $retryAfter),
                    ];
                }

                $evaluationContext->decisionPath = DecisionPath::Throttled;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::throttled($name, $retryAfter, $headers);
            }

            if ($evaluationContext->rateLimitHeadersEnabled && $evaluationContext->pendingRateLimitHeaders === null) {
                $evaluationContext->pendingRateLimitHeaders = [
                    'X-RateLimit-Limit' => (string) $limit,
                    'X-RateLimit-Remaining' => (string) $remaining,
                    'X-RateLimit-Reset' => (string) max(1, $retryAfter),
                ];
            }
        }

        return null;
    }

    private function fixedWindowCounter(EvaluationContext $evaluationContext): FixedWindowCounter
    {
        return $this->fixedWindowCounter ??= new FixedWindowCounter($evaluationContext->config->cache);
    }

    private function slidingStrategy(EvaluationContext $evaluationContext): SlidingWindowStrategy
    {
        return $this->slidingStrategy ??= new SlidingWindowStrategy(
            $evaluationContext->config->cache,
            $evaluationContext->config->cacheKeyGenerator(),
            $evaluationContext->config->now(...),
        );
    }
}
