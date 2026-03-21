<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Closure;
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
use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;

/**
 * Backward-compatible forwarding methods from the pre-sections Config API.
 *
 * All methods delegate to the corresponding section object.
 * Use the section API directly instead: $config->safelists->add(), $config->blocklists->owasp(), etc.
 *
 * @deprecated Will be removed in >= 0.4.
 */
trait DeprecatedConfigMethods
{
    // ── Convenience closures ─────────────────────────────────────────────

    /** @deprecated Use $config->safelists->add() instead. */
    public function safelist(string $name, Closure $callback): static
    {
        $this->safelists->add($name, $callback);
        return $this;
    }

    /** @deprecated Use $config->blocklists->add() instead. */
    public function blocklist(string $name, Closure $callback): static
    {
        $this->blocklists->add($name, $callback);
        return $this;
    }

    /** @deprecated Use $config->blocklists->addPatternBackend() instead. */
    public function addPatternBackend(string $name, PatternBackendInterface $patternBackend): static
    {
        $this->blocklists->addPatternBackend($name, $patternBackend);
        return $this;
    }

    /** @deprecated Use $config->blocklists->fromBackend() instead. */
    public function blocklistFromBackend(string $name, string $backendName): static
    {
        $this->blocklists->fromBackend($name, $backendName);
        return $this;
    }

    /** @deprecated Use $config->blocklists->filePatternBackend() instead. */
    public function filePatternBackend(string $name, string $filePath): FilePatternBackend
    {
        return $this->blocklists->filePatternBackend($name, $filePath);
    }

    /**
     * @deprecated Use $config->blocklists->inMemoryPatternBackend() instead.
     * @param list<PatternEntry> $entries
     */
    public function inMemoryPatternBackend(string $name, array $entries = []): InMemoryPatternBackend
    {
        return $this->blocklists->inMemoryPatternBackend($name, $entries);
    }

    /**
     * @deprecated Use $config->blocklists->patternBlocklist() instead.
     * @param list<PatternEntry> $entries
     */
    public function patternBlocklist(string $name, array $entries): InMemoryPatternBackend
    {
        return $this->blocklists->patternBlocklist($name, $entries);
    }

    /** @deprecated Use $config->blocklists->filePatternBlocklist() instead. */
    public function filePatternBlocklist(string $name, string $filePath): FilePatternBackend
    {
        return $this->blocklists->filePatternBlocklist($name, $filePath);
    }

    /** @deprecated Use $config->blocklists->fileIp() instead. */
    public function fileIpBlocklist(string $name, string $filePath, ?callable $ipResolver = null): FileIpBlocklistStore
    {
        return $this->blocklists->fileIp($name, $filePath, $ipResolver);
    }

    /** @deprecated Use $config->blocklists->owasp() instead. */
    public function owaspBlocklist(string $name, CoreRuleSet $coreRuleSet): static
    {
        $this->blocklists->owasp($name, $coreRuleSet);
        return $this;
    }

    /**
     * @deprecated Use $config->throttles->add() instead.
     */
    public function throttle(string $name, int|\Closure $limit, int|\Closure $period, Closure $key): static
    {
        $this->throttles->add($name, $limit, $period, $key);
        return $this;
    }

    /** @deprecated Use $config->fail2ban->add() instead. */
    public function fail2ban(string $name, int $threshold, int $period, int $ban, Closure $filter, Closure $key): static
    {
        $this->fail2ban->add($name, $threshold, $period, $ban, $filter, $key);
        return $this;
    }

    /** @deprecated Use $config->tracks->add() instead. */
    public function track(string $name, int $period, Closure $filter, Closure $key, ?int $limit = null): static
    {
        $this->tracks->add($name, $period, $filter, $key, $limit);
        return $this;
    }

    // ── Typed registration ───────────────────────────────────────────────

    /** @deprecated Use $config->safelists->addRule() instead. */
    public function addSafelist(SafelistRule $safelistRule): static
    {
        $this->safelists->addRule($safelistRule);
        return $this;
    }

    /** @deprecated Use $config->blocklists->addRule() instead. */
    public function addBlocklist(BlocklistRule $blocklistRule): static
    {
        $this->blocklists->addRule($blocklistRule);
        return $this;
    }

    /** @deprecated Use $config->throttles->addRule() instead. */
    public function addThrottle(ThrottleRule $throttleRule): static
    {
        $this->throttles->addRule($throttleRule);
        return $this;
    }

    /** @deprecated Use $config->fail2ban->addRule() instead. */
    public function addFail2Ban(Fail2BanRule $fail2BanRule): static
    {
        $this->fail2ban->addRule($fail2BanRule);
        return $this;
    }

    /** @deprecated Use $config->tracks->addRule() instead. */
    public function addTrack(TrackRule $trackRule): static
    {
        $this->tracks->addRule($trackRule);
        return $this;
    }

    // ── Getters ──────────────────────────────────────────────────────────

    /**
     * @deprecated Access $config->safelists->rules() instead.
     * @return array<string, SafelistRule>
     */
    public function getSafelistRules(): array
    {
        return $this->safelists->rules();
    }

    /**
     * @deprecated Access $config->blocklists->rules() instead.
     * @return array<string, BlocklistRule>
     */
    public function getBlocklistRules(): array
    {
        return $this->blocklists->rules();
    }

    /**
     * @deprecated Access $config->blocklists->patternBackends() instead.
     * @return array<string, PatternBackendInterface>
     */
    public function getPatternBackends(): array
    {
        return $this->blocklists->patternBackends();
    }

    /**
     * @deprecated Access $config->throttles->rules() instead.
     * @return array<string, ThrottleRule>
     */
    public function getThrottleRules(): array
    {
        return $this->throttles->rules();
    }

    /**
     * @deprecated Access $config->fail2ban->rules() instead.
     * @return array<string, Fail2BanRule>
     */
    public function getFail2BanRules(): array
    {
        return $this->fail2ban->rules();
    }

    /**
     * @deprecated Access $config->tracks->rules() instead.
     * @return array<string, TrackRule>
     */
    public function getTrackRules(): array
    {
        return $this->tracks->rules();
    }

    // ── Diagnostics (delegated to event dispatcher if it's a DiagnosticsCounters) ──

    /** @deprecated Register DiagnosticsCounters as event dispatcher instead. */
    public function incrementDiagnosticsCounter(string $category, ?string $rule = null): void
    {
        if ($this->eventDispatcher instanceof DiagnosticsCounters) {
            $this->eventDispatcher->increment($category, $rule);
        }
    }

    /** @deprecated Register DiagnosticsCounters as event dispatcher instead. */
    public function resetDiagnosticsCounters(): void
    {
        if ($this->eventDispatcher instanceof DiagnosticsCounters) {
            $this->eventDispatcher->reset();
        }
    }

    /**
     * @deprecated Register DiagnosticsCounters as event dispatcher instead.
     * @return array<string, array{total:int, by_rule: array<string,int> }>
     */
    public function getDiagnosticsCounters(): array
    {
        if ($this->eventDispatcher instanceof DiagnosticsCounters) {
            return $this->eventDispatcher->all();
        }

        return [];
    }

    // ── Response factories (delegated) ───────────────────────────────────

    /** @deprecated Assign $config->blocklistedResponseFactory directly. */
    public function blocklistedResponse(Closure $factory): static
    {
        $this->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory($factory);
        return $this;
    }

    /** @deprecated Assign $config->throttledResponseFactory directly. */
    public function throttledResponse(Closure $factory): static
    {
        $this->throttledResponseFactory = new ClosureThrottledResponseFactory($factory);
        return $this;
    }

    /** @deprecated Assign $config->blocklistedResponseFactory directly. */
    public function setBlocklistedResponseFactory(BlocklistedResponseFactoryInterface $blocklistedResponseFactory): static
    {
        $this->blocklistedResponseFactory = $blocklistedResponseFactory;
        return $this;
    }

    /** @deprecated Read $config->blocklistedResponseFactory directly. */
    public function getBlocklistedResponseFactory(): ?BlocklistedResponseFactoryInterface
    {
        return $this->blocklistedResponseFactory;
    }

    /** @deprecated Assign $config->throttledResponseFactory directly. */
    public function setThrottledResponseFactory(ThrottledResponseFactoryInterface $throttledResponseFactory): static
    {
        $this->throttledResponseFactory = $throttledResponseFactory;
        return $this;
    }

    /** @deprecated Read $config->throttledResponseFactory directly. */
    public function getThrottledResponseFactory(): ?ThrottledResponseFactoryInterface
    {
        return $this->throttledResponseFactory;
    }
}
