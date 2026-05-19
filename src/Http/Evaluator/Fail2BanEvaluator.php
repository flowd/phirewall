<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates fail2ban rules: blocks already-banned keys and bans keys that reach the threshold.
 *
 * threshold = N: increment the failure counter on each match; ban on the Nth match.
 * Both pre-handler matches (filter()->match()) and post-handler recorded failures share
 * this single semantic via incrementAndBanIfNeeded().
 */
final readonly class Fail2BanEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $cache = $evaluationContext->config->cache;

        foreach ($evaluationContext->config->fail2ban->rules() as $fail2BanRule) {
            $name = $fail2BanRule->name();
            $key = $fail2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedKey = ($evaluationContext->normalize)((string) $key);
            $banKey = $evaluationContext->config->cacheKeyGenerator()->fail2BanBanKey($name, $normalizedKey);
            if ($cache->has($banKey)) {
                $evaluationContext->decisionPath = DecisionPath::Fail2BanBlocked;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }

            // threshold=N: ban on the Nth matching request (>= comparison).
            if (
                $fail2BanRule->filter()->match($serverRequest)->isMatch()
                && $this->incrementAndBanIfNeeded($fail2BanRule, $normalizedKey, $serverRequest, $evaluationContext)
            ) {
                $evaluationContext->decisionPath = DecisionPath::Fail2BanBanned;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }
        }

        return null;
    }

    /**
     * Increment the fail counter and ban if the threshold has been reached.
     *
     * @return bool True if the key was banned by this call.
     */
    public function incrementAndBanIfNeeded(
        Fail2BanRule $fail2BanRule,
        string $normalizedKey,
        ServerRequestInterface $serverRequest,
        EvaluationContext $evaluationContext,
    ): bool {
        $ruleName = $fail2BanRule->name();
        $failKey = $evaluationContext->config->cacheKeyGenerator()->fail2BanFailKey($ruleName, $normalizedKey);
        $count = $evaluationContext->counter->increment($failKey, $fail2BanRule->period())->count;

        if ($count < $fail2BanRule->threshold()) {
            return false;
        }

        $evaluationContext->config->banManager()->ban($ruleName, $normalizedKey, $fail2BanRule->banSeconds(), BanType::Fail2Ban);

        $evaluationContext->dispatch(new Fail2BanBanned(
            rule: $ruleName,
            key: $normalizedKey,
            threshold: $fail2BanRule->threshold(),
            period: $fail2BanRule->period(),
            banSeconds: $fail2BanRule->banSeconds(),
            count: $count,
            serverRequest: $serverRequest,
        ));

        return true;
    }
}
