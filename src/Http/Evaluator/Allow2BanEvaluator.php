<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Evaluates allow2ban rules: counts all requests per key and bans when the threshold is exceeded.
 *
 * Processes ALL rules so every counter is incremented, then returns the first block.
 * Uses > threshold so N requests are allowed and the (N+1)th triggers the ban.
 * Retry-After is always included. X-Phirewall headers are conditional on responseHeadersEnabled.
 */
final readonly class Allow2BanEvaluator implements EvaluatorInterface
{
    public function evaluate(ServerRequestInterface $serverRequest, EvaluationContext $evaluationContext): ?FirewallResult
    {
        $cache = $evaluationContext->config->cache;

        /** @var array{path: DecisionPath, rule: string, result: FirewallResult}|null $firstBlock */
        $firstBlock = null;

        foreach ($evaluationContext->config->allow2ban->rules() as $allow2BanRule) {
            $name = $allow2BanRule->name();
            $key = $allow2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedKey = ($evaluationContext->normalize)((string) $key);
            $banKey = $evaluationContext->config->cacheKeyGenerator()->allow2BanBanKey($name, $normalizedKey);
            if ($cache->has($banKey)) {
                $banRetryAfter = $this->ttlRemaining($cache, $banKey);
                if ($banRetryAfter < 1) {
                    $banRetryAfter = $allow2BanRule->banSeconds();
                }

                if ($firstBlock === null) {
                    $blockedHeaders = ['Retry-After' => (string) $banRetryAfter]
                        + $evaluationContext->responseHeaders('allow2ban', $name);
                    $firstBlock = [
                        'path' => DecisionPath::Allow2BanBlocked,
                        'rule' => $name,
                        'result' => FirewallResult::blocked($name, 'allow2ban', $blockedHeaders),
                    ];
                }

                continue;
            }

            $hitKey = $evaluationContext->config->cacheKeyGenerator()->allow2BanHitKey($name, $normalizedKey);
            $count = $evaluationContext->counter->increment($hitKey, $allow2BanRule->period())->count;

            if ($count > $allow2BanRule->threshold()) {
                $evaluationContext->config->banManager()->ban($name, $normalizedKey, $allow2BanRule->banSeconds(), BanType::Allow2Ban);
                $cache->delete($hitKey);

                $evaluationContext->dispatch(new Allow2BanBanned(
                    rule: $name,
                    key: $normalizedKey,
                    threshold: $allow2BanRule->threshold(),
                    period: $allow2BanRule->period(),
                    banSeconds: $allow2BanRule->banSeconds(),
                    count: $count,
                    serverRequest: $serverRequest,
                ));

                $newBanRetryAfter = $this->ttlRemaining($cache, $banKey);
                if ($newBanRetryAfter < 1) {
                    $newBanRetryAfter = $allow2BanRule->banSeconds();
                }

                if ($firstBlock === null) {
                    $bannedHeaders = ['Retry-After' => (string) $newBanRetryAfter]
                        + $evaluationContext->responseHeaders('allow2ban', $name);
                    $firstBlock = [
                        'path' => DecisionPath::Allow2BanBanned,
                        'rule' => $name,
                        'result' => FirewallResult::blocked($name, 'allow2ban', $bannedHeaders),
                    ];
                }
            }
        }

        if ($firstBlock !== null) {
            $evaluationContext->decisionPath = $firstBlock['path'];
            $evaluationContext->decisionRule = $firstBlock['rule'];

            return $firstBlock['result'];
        }

        return null;
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
