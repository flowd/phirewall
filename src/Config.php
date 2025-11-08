<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;

final class Config
{
    /**
     * Convenience builder methods: accept closures for ergonomics, but store typed rule objects internally.
     * These are not legacy getters; they simply wrap closures into typed adapters.
     */
    public function safelist(string $name, Closure $callback): self
    {
        return $this->addSafelist(new SafelistRule($name, new ClosureRequestMatcher($callback)));
    }

    public function blocklist(string $name, Closure $callback): self
    {
        return $this->addBlocklist(new BlocklistRule($name, new ClosureRequestMatcher($callback)));
    }

    public function throttle(string $name, int $limit, int $period, Closure $key): self
    {
        return $this->addThrottle(new ThrottleRule($name, $limit, $period, new ClosureKeyExtractor($key)));
    }

    public function fail2ban(string $name, int $threshold, int $period, int $ban, Closure $filter, Closure $key): self
    {
        return $this->addFail2Ban(new Fail2BanRule($name, $threshold, $period, $ban, new ClosureRequestMatcher($filter), new ClosureKeyExtractor($key)));
    }

    public function track(string $name, int $period, Closure $filter, Closure $key): self
    {
        return $this->addTrack(new TrackRule($name, $period, new ClosureRequestMatcher($filter), new ClosureKeyExtractor($key)));
    }

    public function blocklistedResponse(Closure $factory): self
    {
        return $this->setBlocklistedResponseFactory(new ClosureBlocklistedResponseFactory($factory));
    }

    public function throttledResponse(Closure $factory): self
    {
        return $this->setThrottledResponseFactory(new ClosureThrottledResponseFactory($factory));
    }

    /** @var array<string, SafelistRule> */
    private array $safelistRules = [];

    /** @var array<string, BlocklistRule> */
    private array $blocklistRules = [];

    /** @var array<string, ThrottleRule> */
    private array $throttleRules = [];

    /** @var array<string, Fail2BanRule> */
    private array $fail2BanRules = [];

    /** @var array<string, TrackRule> */
    private array $trackRules = [];

    private ?BlocklistedResponseFactoryInterface $blocklistedResponseFactory = null;

    private ?ThrottledResponseFactoryInterface $throttledResponseFactory = null;

    private bool $rateLimitHeadersEnabled = false;

    private string $keyPrefix = 'phirewall';

    /**
     * Lightweight diagnostics counters for testing and observability.
     * Structure: [category => ['total' => int, 'by_rule' => array<string,int>]]
     * @var array<string, array{total:int, by_rule: array<string,int> }>
     */
    private array $diagnosticsCounters = [];

    public function __construct(
        public readonly CacheInterface $cache,
        public readonly ?EventDispatcherInterface $eventDispatcher = null,
    ) {
    }

    // Registration API (typed only)
    public function addSafelist(SafelistRule $safelistRule): self
    {
        $this->safelistRules[$safelistRule->name()] = $safelistRule;
        return $this;
    }

    public function addBlocklist(BlocklistRule $blocklistRule): self
    {
        $this->blocklistRules[$blocklistRule->name()] = $blocklistRule;
        return $this;
    }

    public function addThrottle(ThrottleRule $throttleRule): self
    {
        $this->throttleRules[$throttleRule->name()] = $throttleRule;
        return $this;
    }

    public function addFail2Ban(Fail2BanRule $fail2BanRule): self
    {
        $this->fail2BanRules[$fail2BanRule->name()] = $fail2BanRule;
        return $this;
    }

    public function addTrack(TrackRule $trackRule): self
    {
        $this->trackRules[$trackRule->name()] = $trackRule;
        return $this;
    }

    // Typed response factories
    public function setBlocklistedResponseFactory(BlocklistedResponseFactoryInterface $blocklistedResponseFactory): self
    {
        $this->blocklistedResponseFactory = $blocklistedResponseFactory;
        return $this;
    }

    public function getBlocklistedResponseFactory(): ?BlocklistedResponseFactoryInterface
    {
        return $this->blocklistedResponseFactory;
    }

    public function setThrottledResponseFactory(ThrottledResponseFactoryInterface $throttledResponseFactory): self
    {
        $this->throttledResponseFactory = $throttledResponseFactory;
        return $this;
    }

    public function getThrottledResponseFactory(): ?ThrottledResponseFactoryInterface
    {
        return $this->throttledResponseFactory;
    }

    public function enableRateLimitHeaders(bool $enabled = true): self
    {
        $this->rateLimitHeadersEnabled = $enabled;
        return $this;
    }

    public function rateLimitHeadersEnabled(): bool
    {
        return $this->rateLimitHeadersEnabled;
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

    /**
     * Increment diagnostics counter for a given category and optional rule name.
     */
    public function incrementDiagnosticsCounter(string $category, ?string $rule = null): void
    {
        if (!isset($this->diagnosticsCounters[$category])) {
            $this->diagnosticsCounters[$category] = ['total' => 0, 'by_rule' => []];
        }

        ++$this->diagnosticsCounters[$category]['total'];
        if ($rule !== null) {
            if (!isset($this->diagnosticsCounters[$category]['by_rule'][$rule])) {
                $this->diagnosticsCounters[$category]['by_rule'][$rule] = 0;
            }

            ++$this->diagnosticsCounters[$category]['by_rule'][$rule];
        }
    }

    /**
     * Reset all diagnostics counters (useful for unit tests).
     */
    public function resetDiagnosticsCounters(): void
    {
        $this->diagnosticsCounters = [];
    }

    /**
     * Get a snapshot of diagnostics counters.
     * @return array<string, array{total:int, by_rule: array<string,int> }>
     */
    public function getDiagnosticsCounters(): array
    {
        return $this->diagnosticsCounters;
    }

    /**
     * Typed API: return rule collections.
     * @return array<string, SafelistRule>
     */
    public function getSafelistRules(): array
    {
        return $this->safelistRules;
    }

    /**
     * @return array<string, BlocklistRule>
     */
    public function getBlocklistRules(): array
    {
        return $this->blocklistRules;
    }

    /**
     * @return array<string, ThrottleRule>
     */
    public function getThrottleRules(): array
    {
        return $this->throttleRules;
    }

    /**
     * @return array<string, Fail2BanRule>
     */
    public function getFail2BanRules(): array
    {
        return $this->fail2BanRules;
    }

    /**
     * @return array<string, TrackRule>
     */
    public function getTrackRules(): array
    {
        return $this->trackRules;
    }
}
