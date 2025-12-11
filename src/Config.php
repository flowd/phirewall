<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistStore;
use Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface;
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Owasp\CoreRuleSet;
use Flowd\Phirewall\Owasp\CoreRuleSetMatcher;
use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;
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

    public function addPatternBackend(string $name, PatternBackendInterface $patternBackend): self
    {
        $this->patternBackends[$name] = $patternBackend;
        return $this;
    }

    public function blocklistFromBackend(string $name, string $backendName): self
    {
        if (!isset($this->patternBackends[$backendName])) {
            throw new \InvalidArgumentException(sprintf('Pattern backend "%s" is not registered.', $backendName));
        }

        $snapshotBlocklistMatcher = new SnapshotBlocklistMatcher($this->patternBackends[$backendName]);
        return $this->addBlocklist(new BlocklistRule($name, $snapshotBlocklistMatcher));
    }

    public function filePatternBackend(string $name, string $filePath): FilePatternBackend
    {
        $filePatternBackend = new FilePatternBackend($filePath);
        $this->addPatternBackend($name, $filePatternBackend);
        return $filePatternBackend;
    }

    /**
     * Convenience to block requests whose client IP appears in a file-backed list.
     * Exposes the underlying store so callers can append IPs in-process while also
     * allowing third parties to replace the file externally.
     */
    public function fileIpBlocklist(string $name, string $filePath, ?callable $ipResolver = null): FileIpBlocklistStore
    {
        $fileIpBlocklistStore = new FileIpBlocklistStore($filePath);
        $fileIpBlocklistMatcher = new Config\FileIpBlocklistMatcher($filePath, $ipResolver);
        $this->addBlocklist(new BlocklistRule($name, $fileIpBlocklistMatcher));
        return $fileIpBlocklistStore;
    }

    /**
     * Shorthand to register an OWASP Core Rule Set as a blocklist matcher.
     * Users can enable/disable rule IDs using the provided CoreRuleSet instance.
     */
    public function owaspBlocklist(string $name, CoreRuleSet $coreRuleSet): self
    {
        return $this->addBlocklist(new BlocklistRule($name, new CoreRuleSetMatcher($coreRuleSet)));
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

    /** @var array<string, PatternBackendInterface> */
    private array $patternBackends = [];

    /** @var array<string, ThrottleRule> */
    private array $throttleRules = [];

    /** @var array<string, Fail2BanRule> */
    private array $fail2BanRules = [];

    /** @var array<string, TrackRule> */
    private array $trackRules = [];

    private ?BlocklistedResponseFactoryInterface $blocklistedResponseFactory = null;

    private ?ThrottledResponseFactoryInterface $throttledResponseFactory = null;

    private bool $rateLimitHeadersEnabled = false;

    private bool $owaspDiagnosticsHeaderEnabled = false;

    private string $keyPrefix = 'phirewall';

    /**
     * Lightweight diagnostics counters for testing and observability.
     * Structure: [category => ['total' => int, 'by_rule' => array<string,int>]]
     * @var array<string, array{total:int, by_rule: array<string,int> }>
     */
    private array $diagnosticsCounters = [];

    /**
     * Maximum number of distinct rule entries kept per diagnostics category.
     * Once the cap is reached, additional rules still contribute to the
     * category "total" counter but are not tracked individually in "by_rule".
     */
    private int $diagnosticsMaxRulesPerCategory = 100;

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
            $byRule =& $this->diagnosticsCounters[$category]['by_rule'];

            if (!array_key_exists($rule, $byRule)) {
                // Enforce cap on distinct rules per category
                if (count($byRule) >= $this->diagnosticsMaxRulesPerCategory) {
                    return;
                }

                $byRule[$rule] = 0;
            }

            ++$byRule[$rule];
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
     * @return array<string, PatternBackendInterface>
     */
    public function getPatternBackends(): array
    {
        return $this->patternBackends;
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
