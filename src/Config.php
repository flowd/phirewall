<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Config\DeprecatedConfigMethods;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Section\BlocklistSection;
use Flowd\Phirewall\Config\Section\Fail2BanSection;
use Flowd\Phirewall\Config\Section\SafelistSection;
use Flowd\Phirewall\Config\Section\ThrottleSection;
use Flowd\Phirewall\Config\Section\TrackSection;
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

    public readonly TrackSection $tracks;

    // ── Response factories ───────────────────────────────────────────────

    public ?BlocklistedResponseFactoryInterface $blocklistedResponseFactory = null;

    public ?ThrottledResponseFactoryInterface $throttledResponseFactory = null;

    // ── Settings ─────────────────────────────────────────────────────────

    private bool $rateLimitHeadersEnabled = false;

    private bool $owaspDiagnosticsHeaderEnabled = false;

    private string $keyPrefix = 'phirewall';

    /** @var (\Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null */
    private ?\Closure $ipResolver = null;

    public function __construct(
        public readonly CacheInterface $cache,
        public readonly ?EventDispatcherInterface $eventDispatcher = null,
    ) {
        $this->safelists = new SafelistSection($this);
        $this->blocklists = new BlocklistSection($this);
        $this->throttles = new ThrottleSection();
        $this->fail2ban = new Fail2BanSection();
        $this->tracks = new TrackSection();
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
        return $this;
    }

    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }
}
