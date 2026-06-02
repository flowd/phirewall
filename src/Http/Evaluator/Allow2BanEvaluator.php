<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Evaluates allow2ban rules: counts all requests per key and bans when the threshold is reached.
 *
 * Processes ALL rules so every counter is incremented, then returns the first block.
 * threshold = N: increment on each request; ban on the Nth request (>= comparison).
 * Retry-After is always included. X-Phirewall headers are conditional on responseHeadersEnabled.
 *
 * Unlike Fail2BanEvaluator (which early-returns on its first decision), this evaluator must
 * keep looping after it has decided to block, so that each rule whose key is not already banned
 * still has its hit counter incremented for the request (an already-banned key is skipped). The
 * first blocking decision is captured in an Allow2BanDecision and applied once the loop is done.
 *
 * The per-rule ban-key existence checks are batched into a SINGLE getMultiple() (an MGET on
 * Redis, one SELECT on PDO) at the start of evaluation, so the common "nothing banned" path
 * costs one cache round-trip regardless of the number of allow2ban rules. The Retry-After TTL
 * lookup is deferred to the at-most-once block construction, so the common path performs no TTL
 * round-trips at all. When a rule bans within the loop, its ban key is written back into the
 * batched snapshot, so a later rule whose name normalizes to the same key still observes the ban
 * (as a live existence check would) and skips re-banning the shared key. The batch is therefore
 * behaviour-preserving even though the loop continues after the first block is captured.
 */
final readonly class Allow2BanEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $cache = $evaluationContext->config->cache;
        $cacheKeyGenerator = $evaluationContext->config->cacheKeyGenerator();

        /** @var list<array{rule: Allow2BanRule, normalizedKey: string, banKey: string}> $candidates */
        $candidates = [];
        $banKeys = [];
        foreach ($evaluationContext->config->allow2ban->rules() as $allow2BanRule) {
            $name = $allow2BanRule->name();
            $key = $allow2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedKey = ($evaluationContext->normalize)((string) $key);
            $banKey = $cacheKeyGenerator->allow2BanBanKey($name, $normalizedKey);
            $candidates[] = [
                'rule' => $allow2BanRule,
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

        $capturedDecision = null;
        foreach ($candidates as $candidate) {
            if ($bannedByKey[$candidate['banKey']] ?? false) {
                $capturedDecision ??= $this->buildBlock(
                    DecisionPath::Allow2BanBlocked,
                    $candidate['rule'],
                    $candidate['banKey'],
                    $cache,
                    $evaluationContext,
                );

                continue;
            }

            if ($this->incrementAndBanIfNeeded($candidate['rule'], $candidate['normalizedKey'], $serverRequest, $evaluationContext)) {
                // Keep the batched snapshot consistent: a later rule whose name normalizes to the
                // same ban key must see this ban (as a live existence check would) and skip its own
                // increment instead of re-banning the shared key.
                $bannedByKey[$candidate['banKey']] = true;
                $capturedDecision ??= $this->buildBlock(
                    DecisionPath::Allow2BanBanned,
                    $candidate['rule'],
                    $candidate['banKey'],
                    $cache,
                    $evaluationContext,
                );
            }
        }

        if ($capturedDecision instanceof Allow2BanDecision) {
            $evaluationContext->decisionPath = $capturedDecision->decisionPath;
            $evaluationContext->decisionRule = $capturedDecision->rule;

            return $capturedDecision->result;
        }

        return null;
    }

    /**
     * Build the captured block decision for a rule: resolve Retry-After (the ban
     * key's remaining TTL, falling back to the rule's configured banSeconds when
     * the TTL is unavailable), assemble the response headers, and wrap them in a
     * FirewallResult. Shared by the already-banned and just-banned branches so the
     * two cannot drift apart.
     */
    private function buildBlock(
        DecisionPath $decisionPath,
        Allow2BanRule $allow2BanRule,
        string $banKey,
        CacheInterface $cache,
        EvaluationContext $evaluationContext,
    ): Allow2BanDecision {
        $name = $allow2BanRule->name();

        $retryAfter = $this->ttlRemaining($cache, $banKey);
        if ($retryAfter < 1) {
            $retryAfter = $allow2BanRule->banSeconds();
        }

        $headers = ['Retry-After' => (string) $retryAfter]
            + $evaluationContext->responseHeaders('allow2ban', $name);

        return new Allow2BanDecision(
            $decisionPath,
            $name,
            FirewallResult::blocked($name, 'allow2ban', $headers),
        );
    }

    /**
     * Increment the hit counter and ban if the threshold has been reached.
     *
     * Shared between the pre-handler evaluate() loop and the post-handler
     * RequestContext::recordHit() path so both go through the same
     * increment-and-ban semantic.
     *
     * @return bool True if the key was banned by this call.
     */
    public function incrementAndBanIfNeeded(
        Allow2BanRule $allow2BanRule,
        string $normalizedKey,
        ServerRequestInterface $serverRequest,
        EvaluationContext $evaluationContext,
    ): bool {
        $name = $allow2BanRule->name();
        $hitKey = $evaluationContext->config->cacheKeyGenerator()->allow2BanHitKey($name, $normalizedKey);
        $count = $evaluationContext->counter->increment($hitKey, $allow2BanRule->period())->count;

        if ($count < $allow2BanRule->threshold()) {
            return false;
        }

        $evaluationContext->config->banManager()->ban($name, $normalizedKey, $allow2BanRule->banSeconds(), BanType::Allow2Ban);
        $evaluationContext->config->cache->delete($hitKey);

        $evaluationContext->dispatch(new Allow2BanBanned(
            rule: $name,
            key: $normalizedKey,
            threshold: $allow2BanRule->threshold(),
            period: $allow2BanRule->period(),
            banSeconds: $allow2BanRule->banSeconds(),
            count: $count,
            serverRequest: $serverRequest,
        ));

        return true;
    }

    private function ttlRemaining(CacheInterface $cache, string $key): int
    {
        if ($cache instanceof CounterStoreInterface) {
            return $cache->ttlRemaining($key);
        }

        $entry = $cache->get($key);
        if (!is_array($entry) || !is_scalar($entry['count'] ?? null)) {
            return 0;
        }

        $expiresAt = (int) ($entry['expires_at'] ?? 0);
        $now = time();
        $remaining = $expiresAt - $now;

        return max($remaining, 0);
    }
}
