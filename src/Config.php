<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Config\DeprecatedConfigMethods;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Section\Allow2BanSection;
use Flowd\Phirewall\Config\Section\BlocklistSection;
use Flowd\Phirewall\Config\Section\Fail2BanSection;
use Flowd\Phirewall\Config\Section\SafelistSection;
use Flowd\Phirewall\Config\Section\ThrottleSection;
use Flowd\Phirewall\Config\Section\TrackSection;
use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\CacheKeyRules;
use Flowd\Phirewall\Store\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Central, mutable configuration for a Phirewall deployment.
 *
 * For runtime management of live firewall state (inspecting bans, resetting
 * throttle/fail2ban counters) construct a {@see Http\Firewall}
 * over this Config; it is the supported runtime-management entry point and
 * shares all cached state with the {@see Middleware}.
 */
final class Config
{
    use DeprecatedConfigMethods;

    // ── Rule sections ────────────────────────────────────────────────────

    public readonly SafelistSection $safelists;

    public readonly BlocklistSection $blocklists;

    public readonly ThrottleSection $throttles;

    public readonly Fail2BanSection $fail2ban;

    public readonly Allow2BanSection $allow2ban;

    public readonly TrackSection $tracks;

    // ── Response factories ───────────────────────────────────────────────

    public ?BlocklistedResponseFactoryInterface $blocklistedResponseFactory = null;

    public ?ThrottledResponseFactoryInterface $throttledResponseFactory = null;

    // ── Settings ─────────────────────────────────────────────────────────

    private bool $enabled = true;

    private bool $rateLimitHeadersEnabled = false;

    private bool $owaspDiagnosticsHeaderEnabled = false;

    private bool $responseHeadersEnabled = false;

    private string $keyPrefix = 'phirewall';

    private ?BanManager $banManager = null;

    private ?CacheKeyGenerator $cacheKeyGenerator = null;

    /** @var (\Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null */
    private ?\Closure $ipResolver = null;

    /** @var (\Closure(string): string)|null */
    private ?\Closure $discriminatorNormalizer = null;

    private bool $failOpen = true;

    public function __construct(
        public readonly CacheInterface $cache,
        public readonly ?EventDispatcherInterface $eventDispatcher = null,
        private readonly ?ClockInterface $clock = null,
    ) {
        $this->safelists = new SafelistSection($this);
        $this->blocklists = new BlocklistSection($this);
        $this->throttles = new ThrottleSection();
        $this->fail2ban = new Fail2BanSection();
        $this->allow2ban = new Allow2BanSection();
        $this->tracks = new TrackSection();
    }

    // ── Composition / layering ───────────────────────────────────────────

    /**
     * Compose a base Config with zero or more overlay Configs into a NEW Config.
     *
     * The typical use case is stacking a vendor baseline + an environment overlay
     * + a tenant overlay + a per-deployment tweak (each often rebuilt from a
     * {@see PortableConfig}). The inputs are never
     * mutated; a fresh composed Config is returned.
     *
     * Merge semantics (overlays are applied left to right, so **later sources
     * win**):
     *
     *  - **Rules** are merged by name within each section (safelists, blocklists,
     *    throttles, fail2ban, allow2ban, tracks). When the same rule NAME appears
     *    in more than one layer, the later layer's rule REPLACES the earlier one
     *    in place — the base ordering is preserved and genuinely new rules are
     *    appended. The result is a union, never a concat-with-duplicates.
     *  - **Pattern backends** (used by pattern blocklists) are likewise merged by
     *    name with later-wins precedence.
     *  - **`enabled`** uses strict **last-layer-wins**: the composed Config takes
     *    the `enabled` value of the highest-priority (last) layer, so an explicit
     *    `enable()` / `disable()` / `setEnabled()` on the winning layer always
     *    takes effect. This is deliberately fail-safe — a firewall must never be
     *    left silently disabled just because a higher-priority layer happened to
     *    hold the default value.
     *  - **Other scalar / object options** (failOpen, keyPrefix, the response
     *    header toggles, the IP resolver, the discriminator normalizer and the
     *    response factories) follow a "last explicit value wins" rule: the value
     *    is taken from the LAST layer whose value differs from the field default.
     *    A layer that simply left an option at its default does not clobber an
     *    explicit value set by an earlier layer; consequently a layer cannot
     *    re-assert a field's DEFAULT value to override a lower layer. Caveat for
     *    the IP resolver: IP-aware matchers (IpMatcher, the file/snapshot IP
     *    blocklists, TrustedBotMatcher) capture their resolver when the rule is
     *    constructed, so the composed resolver applies only to rules added
     *    afterwards — it does not rewrite IP rules carried over from earlier
     *    layers. Set the resolver on each source Config before adding its IP rules.
     *  - **Infrastructure** (the PSR-16 cache, the PSR-14 event dispatcher and the
     *    clock) is inherited from the base layer; overlays do not override it.
     *
     * Rules are shared by reference, which is safe because rule objects are
     * immutable value objects ({@see Config\Rule\RuleInterface}).
     * The one exception is a pattern-backed blocklist rule whose backend a later
     * layer overrides by name: it is rebuilt as a new (equally immutable) rule
     * re-pointed at the winning backend, so that rule is not shared by reference.
     * Pattern backends are ALSO shared live by reference but are not necessarily
     * immutable (e.g. {@see Pattern\InMemoryPatternBackend} can
     * be appended to or cleared): mutating an input layer's backend after
     * composition therefore also affects the composed Config.
     */
    public static function compose(self $base, self ...$overlays): self
    {
        $composed = new self($base->cache, $base->eventDispatcher, $base->clock);
        $layers = [$base, ...$overlays];

        // Merge every layer's pattern backends first (last-wins) so the composed
        // registry already holds the winning backend for each name before any
        // pattern-backed blocklist rule is re-pointed at it below.
        foreach ($layers as $layer) {
            foreach ($layer->blocklists->patternBackends() as $backendName => $patternBackend) {
                $composed->blocklists->addPatternBackend($backendName, $patternBackend);
            }
        }

        $composedBackends = $composed->blocklists->patternBackends();

        foreach ($layers as $layer) {
            foreach ($layer->safelists->rules() as $rule) {
                $composed->safelists->addRule($rule);
            }

            // Re-point pattern-backed rules at the composed (winning) backend so a
            // later layer overriding a backend by name actually applies to rules
            // carried over from earlier layers, instead of the rule silently
            // keeping the backend instance it captured at construction.
            foreach ($layer->blocklists->rules() as $rule) {
                $composed->blocklists->addRule(self::rebindPatternBackend($rule, $composedBackends));
            }

            foreach ($layer->throttles->rules() as $rule) {
                $composed->throttles->addRule($rule);
            }

            foreach ($layer->fail2ban->rules() as $rule) {
                $composed->fail2ban->addRule($rule);
            }

            foreach ($layer->allow2ban->rules() as $rule) {
                $composed->allow2ban->addRule($rule);
            }

            foreach ($layer->tracks->rules() as $rule) {
                $composed->tracks->addRule($rule);
            }
        }

        // `enabled` uses strict last-layer-wins (fail-safe): an explicit
        // enable()/disable() on the highest-priority layer must always take
        // effect, and an ambiguous composition must never leave the firewall
        // silently disabled. Unlike the other scalar options below, holding the
        // default value here does not forfeit the layer's say.
        $composed->setEnabled($layers[array_key_last($layers)]->enabled);
        $composed->setFailOpen(self::lastExplicit(array_map(static fn(self $layer): bool => $layer->failOpen, $layers), true));
        $composed->enableRateLimitHeaders(self::lastExplicit(array_map(static fn(self $layer): bool => $layer->rateLimitHeadersEnabled, $layers), false));
        $composed->enableOwaspDiagnosticsHeader(self::lastExplicit(array_map(static fn(self $layer): bool => $layer->owaspDiagnosticsHeaderEnabled, $layers), false));
        $composed->enableResponseHeaders(self::lastExplicit(array_map(static fn(self $layer): bool => $layer->responseHeadersEnabled, $layers), false));
        $composed->setKeyPrefix(self::lastExplicit(array_map(static fn(self $layer): string => $layer->keyPrefix, $layers), 'phirewall'));

        $ipResolver = self::lastExplicit(array_map(static fn(self $layer): ?\Closure => $layer->ipResolver, $layers), null);
        if ($ipResolver instanceof \Closure) {
            $composed->setIpResolver($ipResolver);
        }

        $discriminatorNormalizer = self::lastExplicit(array_map(static fn(self $layer): ?\Closure => $layer->discriminatorNormalizer, $layers), null);
        if ($discriminatorNormalizer instanceof \Closure) {
            $composed->setDiscriminatorNormalizer($discriminatorNormalizer);
        }

        $composed->blocklistedResponseFactory = self::lastExplicit(
            array_map(static fn(self $layer): ?BlocklistedResponseFactoryInterface => $layer->blocklistedResponseFactory, $layers),
            null,
        );
        $composed->throttledResponseFactory = self::lastExplicit(
            array_map(static fn(self $layer): ?ThrottledResponseFactoryInterface => $layer->throttledResponseFactory, $layers),
            null,
        );

        return $composed;
    }

    /**
     * Re-point a pattern-backed blocklist rule at the composed registry's winning
     * backend. Pattern matchers capture their backend instance at construction;
     * without this a later layer overriding a backend by name would not reach
     * rules carried over from earlier layers (the registry and the rules would
     * disagree). Non-pattern rules, and rules whose backend is unchanged, are
     * returned as-is.
     *
     * @param array<string, PatternBackendInterface> $composedBackends
     */
    private static function rebindPatternBackend(BlocklistRule $blocklistRule, array $composedBackends): BlocklistRule
    {
        $matcher = $blocklistRule->matcher();
        if (!$matcher instanceof SnapshotBlocklistMatcher) {
            return $blocklistRule;
        }

        $backendName = $matcher->backendName();
        if ($backendName === '' || !isset($composedBackends[$backendName])) {
            return $blocklistRule;
        }

        $reboundMatcher = $matcher->withBackend($composedBackends[$backendName]);

        return $reboundMatcher === $matcher ? $blocklistRule : new BlocklistRule($blocklistRule->name(), $reboundMatcher);
    }

    /**
     * Layer one or more overlay Configs on top of this one and return a NEW
     * composed Config, leaving this instance (and every overlay) untouched.
     *
     * Equivalent to {@see Config::compose()} with `$this` as the base; see that
     * method for the full merge and precedence semantics.
     */
    public function mergedWith(self ...$overlays): self
    {
        return self::compose($this, ...$overlays);
    }

    /**
     * Combine this Config with one or more {@see PortableConfig}s and return a
     * NEW composed Config, leaving this instance untouched.
     *
     * Each PortableConfig is materialized on THIS Config's cache (and event
     * dispatcher / clock) — the portable/preset layer never receives a cache
     * itself, so shareable rule data stays decoupled from the stateful counter
     * store. The receiver is the base and each PortableConfig is an overlay
     * applied left to right, so later arguments win on a name clash — the same
     * precedence as {@see compose()} / {@see mergedWith()}.
     *
     * Each materialized layer inherits the receiver's `enabled` state: a
     * PortableConfig cannot express `enabled`, and `compose()` resolves it with
     * strict last-layer-wins, so a fresh (default-enabled) layer would otherwise
     * silently re-enable a disabled receiver. Combining never changes whether
     * the firewall is enabled.
     */
    public function combine(PortableConfig ...$portableConfigs): self
    {
        $layers = array_map(
            fn(PortableConfig $portableConfig): self => $portableConfig->applyTo(
                (new self($this->cache, $this->eventDispatcher, $this->clock))->setEnabled($this->enabled),
            ),
            $portableConfigs,
        );

        return self::compose($this, ...$layers);
    }

    /**
     * Reduce a per-layer list of option values to the one that wins under the
     * "last explicit value wins" rule: the value from the last layer that
     * differs from $default, or $default itself when every layer left it alone.
     *
     * @template TValue
     * @param array<TValue> $values Per-layer values, in precedence order (base first, last overlay last).
     * @param TValue $default The field default; a layer carrying this exact value does not override.
     * @return TValue
     */
    private static function lastExplicit(array $values, mixed $default): mixed
    {
        $winner = $default;
        foreach ($values as $value) {
            if ($value !== $default) {
                $winner = $value;
            }
        }

        return $winner;
    }

    // ── Clock ─────────────────────────────────────────────────────────────

    /**
     * Return the current time as a float (seconds since Unix epoch).
     * Uses the injected clock if available, otherwise microtime(true).
     */
    public function now(): float
    {
        return $this->clock?->now() ?? microtime(true);
    }

    // ── IP Resolution ────────────────────────────────────────────────────

    /**
     * Set a global IP resolver for all IP-aware matchers created through Config sections.
     *
     * Use this when running behind a trusted proxy/load balancer:
     *   $proxy = new TrustedProxyResolver(['10.0.0.0/8']);
     *   $config->setIpResolver(KeyExtractors::clientIp($proxy));
     */
    public function setIpResolver(\Closure $ipResolver): self
    {
        $this->ipResolver = $ipResolver;
        return $this;
    }

    /**
     * @return (\Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null
     */
    public function getIpResolver(): ?\Closure
    {
        return $this->ipResolver;
    }

    // ── Discriminator normalizer ────────────────────────────────────────

    /**
     * Set a normalizer applied to all discriminator keys (throttle, fail2ban, track)
     * before they are used for cache lookups.
     *
     * Common use case: case-insensitive key matching via strtolower().
     *
     * @param \Closure(string): string $normalizer
     */
    public function setDiscriminatorNormalizer(\Closure $normalizer): self
    {
        $this->discriminatorNormalizer = $normalizer;
        return $this;
    }

    /**
     * @return (\Closure(string): string)|null
     */
    public function getDiscriminatorNormalizer(): ?\Closure
    {
        return $this->discriminatorNormalizer;
    }

    // ── Firewall toggle ─────────────────────────────────────────────────

    /**
     * Disable the firewall entirely. All requests will pass through without evaluation.
     */
    public function disable(): self
    {
        $this->enabled = false;
        return $this;
    }

    /**
     * Re-enable the firewall after it has been disabled.
     */
    public function enable(): self
    {
        $this->enabled = true;
        return $this;
    }

    /**
     * Set the firewall enabled state explicitly.
     */
    public function setEnabled(bool $enabled): self
    {
        $this->enabled = $enabled;
        return $this;
    }

    /**
     * Check whether the firewall is currently enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // ── Fail-open / fail-closed ────────────────────────────────────────

    /**
     * Configure whether the middleware should fail open (default) or fail closed.
     *
     * When fail-open (true): if the firewall throws an exception (e.g., cache
     * backend unavailable), the request is allowed through and the error is
     * dispatched as a PSR-14 event for logging.
     *
     * When fail-closed (false): exceptions propagate, resulting in a 500 error.
     * Use this only when blocking is more important than availability.
     */
    public function setFailOpen(bool $failOpen): self
    {
        $this->failOpen = $failOpen;
        return $this;
    }

    public function isFailOpen(): bool
    {
        return $this->failOpen;
    }

    // ── PSR-17 integration ────────────────────────────────────────────────

    /**
     * Configure both blocklisted and throttled response factories using PSR-17 factories.
     *
     * This is a convenience method that creates Psr17BlocklistedResponseFactory and
     * Psr17ThrottledResponseFactory from the given PSR-17 response/stream factories.
     * Providing a StreamFactoryInterface enables response body content; without it,
     * responses will have the correct status code and headers but an empty body.
     */
    public function usePsr17Responses(
        ResponseFactoryInterface $responseFactory,
        ?StreamFactoryInterface $streamFactory = null,
    ): self {
        $this->blocklistedResponseFactory = new Psr17BlocklistedResponseFactory($responseFactory, $streamFactory);
        $this->throttledResponseFactory = new Psr17ThrottledResponseFactory($responseFactory, $streamFactory);

        return $this;
    }

    // ── Toggles ──────────────────────────────────────────────────────────

    public function enableRateLimitHeaders(bool $enabled = true): self
    {
        $this->rateLimitHeadersEnabled = $enabled;
        return $this;
    }

    public function rateLimitHeadersEnabled(): bool
    {
        return $this->rateLimitHeadersEnabled;
    }

    public function enableOwaspDiagnosticsHeader(bool $enabled = true): self
    {
        $this->owaspDiagnosticsHeaderEnabled = $enabled;
        return $this;
    }

    public function owaspDiagnosticsHeaderEnabled(): bool
    {
        return $this->owaspDiagnosticsHeaderEnabled;
    }

    public function enableResponseHeaders(bool $enabled = true): self
    {
        $this->responseHeadersEnabled = $enabled;
        return $this;
    }

    public function responseHeadersEnabled(): bool
    {
        return $this->responseHeadersEnabled;
    }

    public function setKeyPrefix(string $prefix): self
    {
        $normalized = rtrim(trim($prefix), ':');
        if ($normalized === '') {
            throw new \InvalidArgumentException('Key prefix cannot be empty');
        }

        $this->assertKeyPrefixIsCacheSafe($normalized);

        $this->keyPrefix = $normalized;
        $this->cacheKeyGenerator = null;
        return $this;
    }

    /**
     * Reject a key prefix that would produce invalid PSR-16 cache keys.
     *
     * The prefix is concatenated verbatim into every generated cache key, so a
     * prefix carrying a PSR-16 reserved character ({}()/\@:) or a control/whitespace
     * character would pass configuration silently and only surface as an
     * InvalidCacheKeyException on the first cache operation. Failing fast here
     * names the offending character at the call site that introduced it.
     *
     * Mirrors the reserved-character set enforced by the cache backends'
     * {@see Store\KeyValidationTrait}.
     */
    private function assertKeyPrefixIsCacheSafe(string $prefix): void
    {
        // Report the offending character, not the raw prefix: a prefix carrying
        // control/newline bytes would otherwise inject them into any log that
        // records the exception message (CWE-117). The character rules are
        // shared with the cache backends via CacheKeyRules so the two cannot
        // drift apart.
        $illegalCharacter = CacheKeyRules::firstIllegalCharacter($prefix);
        if ($illegalCharacter !== null) {
            throw new \InvalidArgumentException(CacheKeyRules::describeViolation('Key prefix', $illegalCharacter));
        }
    }

    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }

    public function banManager(): BanManager
    {
        return $this->banManager ??= new BanManager($this);
    }

    public function cacheKeyGenerator(): CacheKeyGenerator
    {
        return $this->cacheKeyGenerator ??= new CacheKeyGenerator($this->keyPrefix);
    }
}
