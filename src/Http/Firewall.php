<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Flowd\Phirewall\Throttle\FixedWindowCounter;
use Flowd\Phirewall\Throttle\FixedWindowStrategy;
use Flowd\Phirewall\Throttle\SlidingWindowStrategy;
use Flowd\Phirewall\Throttle\ThrottleStrategyInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class Firewall
{
    /**
     * Shared counter for fail2ban, allow2ban, and track rules.
     *
     * Fixed-window is intentional: these are threshold counters where exact
     * precision at window boundaries is not critical. Sliding-window overhead
     * (3 cache ops vs 1 with CounterStoreInterface, or typically 2 with the
     * PSR-16 fallback) is only justified for throttle rules where clients see
     * rate-limit headers and expect consistent behavior.
     */
    private FixedWindowCounter $counter;

    public function __construct(private Config $config)
    {
        $this->counter = new FixedWindowCounter($config->cache);
    }

    /**
     * Reset a specific throttle counter so the key can make requests again.
     *
     * Deletes the fixed-window throttle cache key for the given rule and discriminator.
     * The key is normalized through the discriminator normalizer (if configured) to
     * ensure the same cache key is deleted regardless of input casing.
     *
     * For multiThrottle rules, reset each sub-rule individually (e.g., 'api:1s', 'api:60s').
     * For throttles with a dynamic period, pass the resolved rule name including the
     * ':p{period}' suffix (e.g., 'myrule:p60').
     */
    public function resetThrottle(string $ruleName, string $key): void
    {
        $normalizedKey = $this->normalizeDiscriminator($key);
        $cacheKey = $this->config->cacheKeyGenerator()->throttleKey($ruleName, $normalizedKey);
        $this->config->cache->delete($cacheKey);
    }

    /**
     * Reset a fail2ban ban and hit counter for a specific key.
     *
     * Delegates ban removal to BanManager and also clears the fail counter.
     * The key is normalized through the discriminator normalizer (if configured) to
     * ensure the same cache keys are cleared regardless of input casing.
     */
    public function resetFail2Ban(string $ruleName, string $key): void
    {
        $normalizedKey = $this->normalizeDiscriminator($key);
        $this->config->banManager()->unban($ruleName, $normalizedKey, BanType::Fail2Ban);

        $failKey = $this->config->cacheKeyGenerator()->fail2BanFailKey($ruleName, $normalizedKey);
        $this->config->cache->delete($failKey);
    }

    /**
     * Check whether a key is currently banned by a given rule.
     *
     * Convenience method that delegates to BanManager.
     * The key is normalized through the discriminator normalizer (if configured) to
     * ensure ban lookups match regardless of input casing.
     */
    public function isBanned(string $ruleName, string $key, BanType $banType = BanType::Fail2Ban): bool
    {
        $normalizedKey = $this->normalizeDiscriminator($key);
        return $this->config->banManager()->isBanned($ruleName, $normalizedKey, $banType);
    }

    /**
     * Clear all cache entries (counters, bans, tracking data).
     *
     * Calls cache->clear() which removes ALL keys in the cache instance.
     * For production use with shared caches (Redis/APCu), use a dedicated
     * cache instance for Phirewall.
     */
    public function resetAll(): void
    {
        $this->config->cache->clear();
    }

    /**
     * Process a single recorded fail2ban failure signal from the RequestContext.
     *
     * Looks up the fail2ban rule by name, normalizes the discriminator key,
     * checks if already banned, increments the fail counter, and bans + dispatches
     * a Fail2BanBanned event if the threshold is reached.
     */
    public function processRecordedFailure(string $ruleName, string $key, ServerRequestInterface $serverRequest): void
    {
        $rules = $this->config->fail2ban->rules();
        $fail2BanRule = $rules[$ruleName] ?? null;
        if ($fail2BanRule === null) {
            return;
        }

        $normalizedKey = $this->normalizeDiscriminator($key);

        $banKey = $this->config->cacheKeyGenerator()->fail2BanBanKey($ruleName, $normalizedKey);
        if ($this->config->cache->has($banKey)) {
            return;
        }

        $failKey = $this->config->cacheKeyGenerator()->fail2BanFailKey($ruleName, $normalizedKey);
        $count = $this->counter->increment($failKey, $fail2BanRule->period())->count;

        // Post-handler: the application already processed the request and explicitly
        // signaled a failure. Use >= so the Nth recorded failure triggers the ban
        // immediately. Compare with decide() which uses > (pre-handler: N matches
        // allowed, ban on N+1).
        if ($count >= $fail2BanRule->threshold()) {
            $this->config->banManager()->ban($ruleName, $normalizedKey, $fail2BanRule->banSeconds(), BanType::Fail2Ban);

            $this->dispatch(new Fail2BanBanned(
                rule: $ruleName,
                key: $normalizedKey,
                threshold: $fail2BanRule->threshold(),
                period: $fail2BanRule->period(),
                banSeconds: $fail2BanRule->banSeconds(),
                count: $count,
                serverRequest: $serverRequest,
            ));
        }
    }

    public function decide(ServerRequestInterface $serverRequest): FirewallResult
    {
        if (!$this->config->isEnabled()) {
            return FirewallResult::pass();
        }

        $start = microtime(true);
        $decisionPath = DecisionPath::Passed;
        $decisionRule = null;

        $pendingRateLimitHeaders = null;

        $discriminatorNormalizer = $this->config->getDiscriminatorNormalizer();
        $normalize = $discriminatorNormalizer instanceof \Closure
            ? $discriminatorNormalizer
            : static fn(string $key): string => $key;

        $includeResponseHeaders = $this->config->responseHeadersEnabled();

        // 0) Track (passive)
        foreach ($this->config->tracks->rules() as $trackRule) {
            $name = $trackRule->name();
            if ($trackRule->filter()->match($serverRequest)->isMatch() === true) {
                $key = $trackRule->keyExtractor()->extract($serverRequest);
                if ($key !== null) {
                    $normalizedKey = $normalize((string) $key);
                    $counterKey = $this->config->cacheKeyGenerator()->trackKey($name, $normalizedKey);
                    $count = $this->counter->increment($counterKey, $trackRule->period())->count;
                    $limit = $trackRule->limit();

                    $this->dispatch(new TrackHit(
                        rule: $name,
                        key: $normalizedKey,
                        period: $trackRule->period(),
                        count: $count,
                        serverRequest: $serverRequest,
                        limit: $limit,
                    ));
                }
            }
        }

        // 1) Safelist
        foreach ($this->config->safelists->rules() as $safelistRule) {
            $name = $safelistRule->name();
            if ($safelistRule->matcher()->match($serverRequest)->isMatch() === true) {
                $this->dispatch(new SafelistMatched($name, $serverRequest));

                $decisionPath = DecisionPath::Safelisted;
                $decisionRule = $name;
                $result = FirewallResult::safelisted($name, $includeResponseHeaders ? ['X-Phirewall-Safelist' => $name] : []);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }
        }

        // 2) Blocklist
        foreach ($this->config->blocklists->rules() as $blocklistRule) {
            $name = $blocklistRule->name();
            $match = $blocklistRule->matcher()->match($serverRequest);
            if ($match->isMatch() === true) {
                $this->dispatch(new BlocklistMatched($name, $serverRequest));

                $headers = $this->responseHeaders($includeResponseHeaders, 'blocklist', $name);
                if ($this->config->owaspDiagnosticsHeaderEnabled() && $match->source() === 'owasp') {
                    $meta = $match->metadata();
                    if (isset($meta['owasp_rule_id'])) {
                        $headers['X-Phirewall-Owasp-Rule'] = (string)$meta['owasp_rule_id'];
                    }
                }

                $decisionPath = DecisionPath::Blocklisted;
                $decisionRule = $name;
                $result = FirewallResult::blocked($name, 'blocklist', $headers);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }
        }

        $cache = $this->config->cache;

        // NOTE: The check → increment → threshold-check sequence is not atomic.
        // Under high concurrency, a small number of requests may slip through
        // at the exact moment the threshold is crossed. This is acceptable for
        // rate-limiting (not a security boundary) and matches fail2ban's pattern.

        // 3) Fail2Ban
        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $name = $fail2BanRule->name();
            $key = $fail2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedFail2BanKey = $normalize((string) $key);
            $banKey = $this->config->cacheKeyGenerator()->fail2BanBanKey($name, $normalizedFail2BanKey);
            if ($cache->has($banKey)) {

                $decisionPath = DecisionPath::Fail2BanBlocked;
                $decisionRule = $name;
                $result = FirewallResult::blocked($name, 'fail2ban', $this->responseHeaders($includeResponseHeaders, 'fail2ban', $name));
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }

            if ($fail2BanRule->filter()->match($serverRequest)->isMatch() === true) {
                $failKey = $this->config->cacheKeyGenerator()->fail2BanFailKey($name, $normalizedFail2BanKey);
                $count = $this->counter->increment($failKey, $fail2BanRule->period())->count;

                // Pre-handler: N filter matches allowed, ban on N+1. Use > so
                // threshold=3 allows 3 matches and bans on the 4th. Compare with
                // processRecordedFailure() which uses >= (post-handler semantics).
                if ($count > $fail2BanRule->threshold()) {
                    $this->config->banManager()->ban($name, $normalizedFail2BanKey, $fail2BanRule->banSeconds(), BanType::Fail2Ban);

                    $this->dispatch(new Fail2BanBanned(
                        rule: $name,
                        key: $normalizedFail2BanKey,
                        threshold: $fail2BanRule->threshold(),
                        period: $fail2BanRule->period(),
                        banSeconds: $fail2BanRule->banSeconds(),
                        count: $count,
                        serverRequest: $serverRequest,
                    ));
                    $decisionPath = DecisionPath::Fail2BanBanned;
                    $decisionRule = $name;
                    $result = FirewallResult::blocked($name, 'fail2ban', $this->responseHeaders($includeResponseHeaders, 'fail2ban', $name));
                    $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                    return $result;
                }
            }
        }

        // 4) Throttle
        foreach ($this->config->throttles->rules() as $throttleRule) {
            $name = $throttleRule->name();
            $key = $throttleRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedThrottleKey = $normalize((string) $key);
            $limit = $throttleRule->resolveLimit($serverRequest);
            $period = $throttleRule->resolvePeriod($serverRequest);
            $strategy = $this->resolveStrategy($throttleRule);

            // When period is dynamic, include the resolved period in the cache key so
            // different periods for the same discriminator get independent counters.
            $effectiveRuleName = $throttleRule->hasDynamicPeriod()
                ? $name . ':p' . $period
                : $name;
            $throttleIncrement = $strategy->increment($effectiveRuleName, $normalizedThrottleKey, $period);

            // ceil() rounds up the floating-point sliding window estimate for a conservative safety margin
            $count = (int) ceil($throttleIncrement->count);
            $retryAfter = $throttleIncrement->retryAfter;
            $remaining = max(0, $limit - $count);

            if ($count > $limit) {
                $this->dispatch(new ThrottleExceeded(
                    rule: $name,
                    key: $normalizedThrottleKey,
                    limit: $limit,
                    period: $period,
                    count: $count,
                    retryAfter: $retryAfter,
                    serverRequest: $serverRequest,
                ));

                $headers = ['Retry-After' => (string)max(1, $retryAfter)]
                    + $this->responseHeaders($includeResponseHeaders, 'throttle', $name);
                if ($this->config->rateLimitHeadersEnabled()) {
                    $headers += [
                        'X-RateLimit-Limit' => (string)$limit,
                        'X-RateLimit-Remaining' => '0',
                        'X-RateLimit-Reset' => (string)max(1, $retryAfter),
                    ];
                }

                $decisionPath = DecisionPath::Throttled;
                $decisionRule = $name;
                $result = FirewallResult::throttled($name, $retryAfter, $headers);
                $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
                return $result;
            }

            if ($this->config->rateLimitHeadersEnabled() && $pendingRateLimitHeaders === null) {
                $pendingRateLimitHeaders = [
                    'X-RateLimit-Limit' => (string)$limit,
                    'X-RateLimit-Remaining' => (string)$remaining,
                    'X-RateLimit-Reset' => (string)max(1, $retryAfter),
                ];
            }
        }

        // 5) Allow2Ban
        // Process all rules so every counter is incremented, then return the first block.
        $allow2BanResult = null;
        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $name = $allow2BanRule->name();
            $key = $allow2BanRule->keyExtractor()->extract($serverRequest);
            if ($key === null) {
                continue;
            }

            $normalizedAllow2BanKey = $normalize((string) $key);
            $a2bBanKey = $this->config->cacheKeyGenerator()->allow2BanBanKey($name, $normalizedAllow2BanKey);
            if ($cache->has($a2bBanKey)) {
                $banRetryAfter = $this->ttlRemaining($a2bBanKey);
                if ($banRetryAfter < 1) {
                    $banRetryAfter = $allow2BanRule->banSeconds();
                }

                if ($allow2BanResult === null) {
                    $blockedHeaders = ['Retry-After' => (string) $banRetryAfter]
                        + $this->responseHeaders($includeResponseHeaders, 'allow2ban', $name);
                    $allow2BanResult = ['path' => DecisionPath::Allow2BanBlocked, 'rule' => $name, 'result' => FirewallResult::blocked($name, 'allow2ban', $blockedHeaders)];
                }

                continue;
            }

            $a2bHitKey = $this->config->cacheKeyGenerator()->allow2BanHitKey($name, $normalizedAllow2BanKey);
            $count = $this->counter->increment($a2bHitKey, $allow2BanRule->period())->count;

            if ($count > $allow2BanRule->threshold()) {
                $this->config->banManager()->ban($name, $normalizedAllow2BanKey, $allow2BanRule->banSeconds(), BanType::Allow2Ban);
                $cache->delete($a2bHitKey);

                $this->dispatch(new Allow2BanBanned(
                    rule: $name,
                    key: $normalizedAllow2BanKey,
                    threshold: $allow2BanRule->threshold(),
                    period: $allow2BanRule->period(),
                    banSeconds: $allow2BanRule->banSeconds(),
                    count: $count,
                    serverRequest: $serverRequest,
                ));
                $newBanRetryAfter = $this->ttlRemaining($a2bBanKey);
                if ($newBanRetryAfter < 1) {
                    $newBanRetryAfter = $allow2BanRule->banSeconds();
                }

                if ($allow2BanResult === null) {
                    $bannedHeaders = ['Retry-After' => (string) $newBanRetryAfter]
                        + $this->responseHeaders($includeResponseHeaders, 'allow2ban', $name);
                    $allow2BanResult = ['path' => DecisionPath::Allow2BanBanned, 'rule' => $name, 'result' => FirewallResult::blocked($name, 'allow2ban', $bannedHeaders)];
                }
            }
        }

        if ($allow2BanResult !== null) {
            $decisionPath = $allow2BanResult['path'];
            $decisionRule = $allow2BanResult['rule'];
            $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
            return $allow2BanResult['result'];
        }


        $result = FirewallResult::pass($pendingRateLimitHeaders ?? []);
        $this->dispatchPerformanceMeasured($start, $decisionPath, $decisionRule);
        return $result;
    }

    private function dispatchPerformanceMeasured(float $start, DecisionPath $decisionPath, ?string $ruleName): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if (!$dispatcher instanceof \Psr\EventDispatcher\EventDispatcherInterface) {
            return;
        }

        $durationMicros = (int) round((microtime(true) - $start) * 1_000_000);
        if ($durationMicros < 0) {
            $durationMicros = 0;
        }

        $dispatcher->dispatch(new PerformanceMeasured($decisionPath, $durationMicros, $ruleName));
    }

    private function resolveStrategy(ThrottleRule $throttleRule): ThrottleStrategyInterface
    {
        /** @var \WeakMap<self, array{fixed: FixedWindowStrategy, sliding: SlidingWindowStrategy}>|null $strategyCache */
        static $strategyCache = null;
        $strategyCache ??= new \WeakMap();

        if (!isset($strategyCache[$this])) {
            $cache = $this->config->cache;
            $cacheKeyGenerator = $this->config->cacheKeyGenerator();

            $strategyCache[$this] = [
                'fixed' => new FixedWindowStrategy($cache, $cacheKeyGenerator),
                'sliding' => new SlidingWindowStrategy($cache, $cacheKeyGenerator, $this->config->now(...)),
            ];
        }

        /** @var array{fixed: FixedWindowStrategy, sliding: SlidingWindowStrategy} $strategies */
        $strategies = $strategyCache[$this];

        return $throttleRule->isSliding()
            ? $strategies['sliding']
            : $strategies['fixed'];
    }


    private function ttlRemaining(string $key): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->ttlRemaining($key);
        }

        $entry = $cache->get($key);
        if (!is_array($entry) || !is_scalar($entry['count'] ?? null)) {
            return 0;
        }

        $expiresAt = (int)($entry['expires_at'] ?? 0);
        $now = time();
        $remaining = $expiresAt - $now;

        return max($remaining, 0);
    }

    /**
     * Normalize a discriminator key using the configured normalizer.
     *
     * Returns the key unchanged when no normalizer is set.
     */
    private function normalizeDiscriminator(string $key): string
    {
        $normalizer = $this->config->getDiscriminatorNormalizer();

        return $normalizer instanceof \Closure ? $normalizer($key) : $key;
    }

    /** @return array<string, string> */
    private function responseHeaders(bool $enabled, string $type, string $rule): array
    {
        return $enabled ? ['X-Phirewall' => $type, 'X-Phirewall-Matched' => $rule] : [];
    }

    private function dispatch(object $event): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if ($dispatcher instanceof \Psr\EventDispatcher\EventDispatcherInterface) {
            $dispatcher->dispatch($event);
        }
    }
}
