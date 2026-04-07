<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Config\DeprecatedConfigMethods;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Section\Allow2BanSection;
use Flowd\Phirewall\Config\Section\BlocklistSection;
use Flowd\Phirewall\Config\Section\Fail2BanSection;
use Flowd\Phirewall\Config\Section\SafelistSection;
use Flowd\Phirewall\Config\Section\ThrottleSection;
use Flowd\Phirewall\Config\Section\TrackSection;
use Flowd\Phirewall\Store\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

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
        $normalized = trim($prefix);
        if ($normalized === '') {
            throw new \InvalidArgumentException('Key prefix cannot be empty');
        }

        $this->keyPrefix = rtrim($normalized, ':');
        $this->cacheKeyGenerator = null;
        return $this;
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
