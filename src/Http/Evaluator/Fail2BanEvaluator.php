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
 *
 * The per-rule ban-key existence checks are batched into a SINGLE getMultiple() (an MGET
 * on Redis, one SELECT on PDO) at the start of evaluation, so the common "nothing banned"
 * path costs one cache round-trip regardless of the number of fail2ban rules instead of one
 * per rule. This evaluator returns on the FIRST decision, so no later rule's ban-key read ever
 * runs after an earlier rule's ban write in the same request; the snapshot is always consulted
 * before it could go stale, so batching upfront is behaviour-preserving.
 */
final readonly class Fail2BanEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $cache = $evaluationContext->config->cache;
        $cacheKeyGenerator = $evaluationContext->config->cacheKeyGenerator();

        /** @var list<array{rule: Fail2BanRule, name: string, normalizedKey: string, banKey: string}> $candidates */
        $candidates = [];
        $banKeys = [];
        foreach ($evaluationContext->config->fail2ban->rules() as $fail2BanRule) {
            $name = $fail2BanRule->name();
            $key = $evaluationContext->config->resolveKey($fail2BanRule->keyExtractor(), $serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedKey = ($evaluationContext->normalize)((string) $key);
            $banKey = $cacheKeyGenerator->fail2BanBanKey($name, $normalizedKey);
            $candidates[] = [
                'rule' => $fail2BanRule,
                'name' => $name,
                'normalizedKey' => $normalizedKey,
                'banKey' => $banKey,
            ];
            $banKeys[$banKey] = true;
        }

        if ($candidates === []) {
            return null;
        }

        // Single batched existence check across every candidate rule's ban key.
        $banEntries = $cache->getMultiple(array_keys($banKeys));
        $bannedByKey = [];
        foreach ($banEntries as $banKey => $banEntry) {
            $bannedByKey[$banKey] = $banEntry !== null;
        }

        foreach ($candidates as $candidate) {
            $name = $candidate['name'];

            if ($bannedByKey[$candidate['banKey']] ?? false) {
                $evaluationContext->decisionPath = DecisionPath::Fail2BanBlocked;
                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }

            // threshold=N: ban on the Nth matching request (>= comparison).
            if (
                $candidate['rule']->filter()->match($serverRequest)->isMatch()
                && $this->incrementAndBanIfNeeded($candidate['rule'], $candidate['normalizedKey'], $serverRequest, $evaluationContext)
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
