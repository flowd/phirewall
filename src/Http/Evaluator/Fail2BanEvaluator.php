<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Fail2BanBlocked;
use Flowd\Phirewall\Events\Fail2BanMatched;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates fail2ban rules: blocks already-banned keys, blocks every filter match,
 * and bans keys that reach the threshold.
 *
 * The filter marks a request as malicious by definition, so any match is blocked (403):
 * a match below the threshold blocks via {@see DecisionPath::Fail2BanMatched} and a
 * {@see Fail2BanMatched} event; the Nth (threshold) match additionally bans the key and
 * blocks via {@see DecisionPath::Fail2BanBanned} and a {@see Fail2BanBanned} event. The
 * banning match dispatches only Fail2BanBanned, never both. A request whose key is
 * already banned blocks via {@see DecisionPath::Fail2BanBlocked} and a
 * {@see Fail2BanBlocked} event without evaluating the filter.
 *
 * threshold = N: increment the failure counter on each match; ban on the Nth match.
 * Pre-handler matches (the rule filter, evaluated with the Config's client-IP resolver)
 * increment via incrementAndBanIfNeeded() and block. Post-handler recorded failures share
 * the same increment-and-ban semantic but never block the current request nor dispatch
 * Fail2BanMatched.
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
    use ResolvesClientIpForMatchers;

    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $cache = $evaluationContext->config->cache;
        $cacheKeyGenerator = $evaluationContext->config->cacheKeyGenerator();
        $defaultIpResolver = $evaluationContext->config->clientIpResolver();

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

                $evaluationContext->dispatch(new Fail2BanBlocked(
                    rule: $name,
                    key: $candidate['normalizedKey'],
                    serverRequest: $serverRequest,
                ));

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }

            // Every filter match is blocked: the Nth match bans (Fail2BanBanned),
            // an earlier match blocks below the threshold (Fail2BanMatched).
            if ($this->matchWithClientIpResolver($candidate['rule']->filter(), $serverRequest, $defaultIpResolver)->isMatch()) {
                $rule = $candidate['rule'];
                $count = $this->incrementAndBanIfNeeded($rule, $candidate['normalizedKey'], $serverRequest, $evaluationContext);

                if ($count >= $rule->threshold()) {
                    $evaluationContext->decisionPath = DecisionPath::Fail2BanBanned;
                } else {
                    $evaluationContext->dispatch(new Fail2BanMatched(
                        rule: $name,
                        key: $candidate['normalizedKey'],
                        threshold: $rule->threshold(),
                        period: $rule->period(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                    $evaluationContext->decisionPath = DecisionPath::Fail2BanMatched;
                }

                $evaluationContext->decisionRule = $name;

                return FirewallResult::blocked($name, 'fail2ban', $evaluationContext->responseHeaders('fail2ban', $name));
            }
        }

        return null;
    }

    /**
     * Increment the fail counter and ban (dispatching {@see Fail2BanBanned}) when
     * the threshold is reached. Shared by the pre-handler match path and the
     * post-handler recorded-failure path; the latter neither blocks nor dispatches
     * {@see Fail2BanMatched}.
     *
     * @return int The failure count after incrementing.
     */
    public function incrementAndBanIfNeeded(
        Fail2BanRule $fail2BanRule,
        string $normalizedKey,
        ServerRequestInterface $serverRequest,
        EvaluationContext $evaluationContext,
    ): int {
        $ruleName = $fail2BanRule->name();
        $failKey = $evaluationContext->config->cacheKeyGenerator()->fail2BanFailKey($ruleName, $normalizedKey);
        $count = $evaluationContext->counter->increment($failKey, $fail2BanRule->period())->count;

        if ($count < $fail2BanRule->threshold()) {
            return $count;
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

        return $count;
    }
}
