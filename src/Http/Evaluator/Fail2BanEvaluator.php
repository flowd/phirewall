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
 * Evaluates fail2ban rules: blocks already-banned keys and bans keys that exceed the threshold.
 *
 * Pre-handler (evaluate): uses > so threshold=3 allows 3 matches, bans on the 4th.
 * Post-handler (incrementAndBanIfNeeded with postHandler: true): uses >= so the Nth
 * recorded failure triggers the ban immediately.
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

            // Pre-handler: use > so threshold=3 allows 3 matches, bans on the 4th.
            if (
                $fail2BanRule->filter()->match($serverRequest)->isMatch()
                && $this->incrementAndBanIfNeeded($fail2BanRule, $normalizedKey, $serverRequest, $evaluationContext, postHandler: false)
            ) {
                $evaluationContext->decisionPath = DecisionPath::Fail2BanBanned;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }
        }

        return null;
    }

    /**
     * Increment the fail counter and ban if the threshold is reached or exceeded.
     *
     * @param bool $postHandler When true (post-handler), uses >= so the Nth failure
     *                          triggers the ban immediately. When false (pre-handler),
     *                          uses > so N matches are allowed and the (N+1)th is banned.
     *
     * @return bool True if the key was banned by this call.
     */
    public function incrementAndBanIfNeeded(
        Fail2BanRule $fail2BanRule,
        string $normalizedKey,
        ServerRequestInterface $serverRequest,
        EvaluationContext $evaluationContext,
        bool $postHandler,
    ): bool {
        $ruleName = $fail2BanRule->name();
        $failKey = $evaluationContext->config->cacheKeyGenerator()->fail2BanFailKey($ruleName, $normalizedKey);
        $count = $evaluationContext->counter->increment($failKey, $fail2BanRule->period())->count;

        $exceeded = $postHandler
            ? $count >= $fail2BanRule->threshold()
            : $count > $fail2BanRule->threshold();

        if (!$exceeded) {
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
