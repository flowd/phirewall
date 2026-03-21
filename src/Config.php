<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Config\DeprecatedConfigMethods;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Section\Allow2BanSection;
use Flowd\Phirewall\Config\Section\BlocklistSection;
use Flowd\Phirewall\Config\Section\Fail2BanSection;
use Flowd\Phirewall\Config\Section\SafelistSection;
use Flowd\Phirewall\Config\Section\ThrottleSection;
use Flowd\Phirewall\Config\Section\TrackSection;
use Flowd\Phirewall\Store\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
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

    private string $keyPrefix = 'phirewall';

    private ?BanManager $banManager = null;

    private ?CacheKeyGenerator $cacheKeyGenerator = null;

    /** @var (\Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null */
    private ?\Closure $ipResolver = null;

    /** @var (\Closure(string): string)|null */
    private ?\Closure $discriminatorNormalizer = null;

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
