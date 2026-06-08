<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RecordedSignal;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Http\Evaluator\Allow2BanEvaluator;
use Flowd\Phirewall\Http\Evaluator\BlocklistEvaluator;
use Flowd\Phirewall\Http\Evaluator\EvaluationContext;
use Flowd\Phirewall\Http\Evaluator\EvaluatorInterface;
use Flowd\Phirewall\Http\Evaluator\Fail2BanEvaluator;
use Flowd\Phirewall\Http\Evaluator\SafelistEvaluator;
use Flowd\Phirewall\Http\Evaluator\ThrottleEvaluator;
use Flowd\Phirewall\Http\Evaluator\TrackEvaluator;
use Flowd\Phirewall\Throttle\FixedWindowCounter;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The supported runtime-management entry point for a Phirewall deployment.
 *
 * Despite living under the Http namespace, this class is part of the public API
 * and is the documented place to inspect and manage live firewall state. Besides
 * driving request evaluation via {@see decide()}, it exposes the operational
 * helpers an admin surface needs: {@see isBanned()}, {@see resetThrottle()},
 * {@see resetFail2Ban()} and {@see resetAll()}.
 *
 * Constructing `new Firewall($config)` directly is fully supported. Firewall is
 * stateless beyond its Config: all persistent state (counters, bans, tracking)
 * lives in the Config's PSR-16 cache, so every Firewall instance built over the
 * same Config (and therefore the same cache) shares that state. An admin tool
 * can construct its own Firewall over the same Config the {@see \Flowd\Phirewall\Middleware}
 * uses and will see (and mutate) exactly the same bans and counters.
 */
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

    /** @var list<EvaluatorInterface> */
    private array $evaluators;

    private Fail2BanEvaluator $fail2BanEvaluator;

    private Allow2BanEvaluator $allow2BanEvaluator;

    public function __construct(private Config $config)
    {
        $this->counter = new FixedWindowCounter($config->cache);
        $this->fail2BanEvaluator = new Fail2BanEvaluator();
        $this->allow2BanEvaluator = new Allow2BanEvaluator();

        $this->evaluators = [
            new TrackEvaluator(),
            new SafelistEvaluator(),
            new BlocklistEvaluator(),
            $this->fail2BanEvaluator,
            new ThrottleEvaluator(),
            $this->allow2BanEvaluator,
        ];
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
     *
     * The ban category must be passed explicitly: allow2ban and fail2ban store
     * bans under distinct cache keys, so an implicit default would silently
     * answer for the wrong category.
     */
    public function isBanned(string $ruleName, string $key, BanType $banType): bool
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
     * Process a single signal recorded by the handler via RequestContext.
     *
     * The signal carries its BanType (Fail2Ban / Allow2Ban) and either an
     * explicit key or null, in which case the matching rule's keyExtractor
     * is run on the current request. Unknown rule names are silently
     * ignored (the handler may post signals defensively without checking
     * config). Already-banned keys short-circuit so a second signal in the
     * same window does not double-count or re-emit the event.
     */
    public function processRecordedSignal(RecordedSignal $recordedSignal, ServerRequestInterface $serverRequest): void
    {
        match ($recordedSignal->banType) {
            BanType::Fail2Ban => $this->processRecordedFail2BanSignal($recordedSignal, $serverRequest),
            BanType::Allow2Ban => $this->processRecordedAllow2BanSignal($recordedSignal, $serverRequest),
        };
    }

    private function processRecordedFail2BanSignal(
        RecordedSignal $recordedSignal,
        ServerRequestInterface $serverRequest,
    ): void {
        $rule = $this->config->fail2ban->rules()[$recordedSignal->ruleName] ?? null;
        if ($rule === null) {
            return;
        }

        $rawKey = $recordedSignal->key ?? $this->config->resolveKey($rule->keyExtractor(), $serverRequest);
        if ($rawKey === null || $rawKey === '') {
            return;
        }

        $normalizedKey = $this->normalizeDiscriminator($rawKey);

        $banKey = $this->config->cacheKeyGenerator()->fail2BanBanKey($recordedSignal->ruleName, $normalizedKey);
        if ($this->config->cache->has($banKey)) {
            return;
        }

        $this->fail2BanEvaluator->incrementAndBanIfNeeded($rule, $normalizedKey, $serverRequest, $this->createContext());
    }

    private function processRecordedAllow2BanSignal(
        RecordedSignal $recordedSignal,
        ServerRequestInterface $serverRequest,
    ): void {
        $rule = $this->config->allow2ban->rules()[$recordedSignal->ruleName] ?? null;
        if ($rule === null) {
            return;
        }

        $rawKey = $recordedSignal->key ?? $this->config->resolveKey($rule->keyExtractor(), $serverRequest);
        if ($rawKey === null || $rawKey === '') {
            return;
        }

        $normalizedKey = $this->normalizeDiscriminator($rawKey);

        $banKey = $this->config->cacheKeyGenerator()->allow2BanBanKey($recordedSignal->ruleName, $normalizedKey);
        if ($this->config->cache->has($banKey)) {
            return;
        }

        $this->allow2BanEvaluator->incrementAndBanIfNeeded($rule, $normalizedKey, $serverRequest, $this->createContext());
    }

    public function decide(ServerRequestInterface $serverRequest): FirewallResult
    {
        if (!$this->config->isEnabled()) {
            return FirewallResult::pass();
        }

        $start = microtime(true);
        $context = $this->createContext();

        foreach ($this->evaluators as $evaluator) {
            $result = $evaluator->evaluate($serverRequest, $context);
            if ($result !== null) {
                $this->dispatchPerformanceMeasured($start, $context->decisionPath, $context->decisionRule);
                return $result;
            }
        }

        $result = FirewallResult::pass($context->pendingRateLimitHeaders ?? []);
        $this->dispatchPerformanceMeasured($start, $context->decisionPath, $context->decisionRule);
        return $result;
    }

    private function createContext(): EvaluationContext
    {
        $discriminatorNormalizer = $this->config->getDiscriminatorNormalizer();
        $normalize = $discriminatorNormalizer instanceof \Closure
            ? $discriminatorNormalizer
            : static fn(string $key): string => $key;

        return new EvaluationContext(
            config: $this->config,
            normalize: $normalize,
            responseHeadersEnabled: $this->config->responseHeadersEnabled(),
            rateLimitHeadersEnabled: $this->config->rateLimitHeadersEnabled(),
            owaspDiagnosticsHeaderEnabled: $this->config->owaspDiagnosticsHeaderEnabled(),
            counter: $this->counter,
        );
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
}
