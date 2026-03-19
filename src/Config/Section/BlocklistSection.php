<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistStore;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Owasp\CoreRuleSet;
use Flowd\Phirewall\Owasp\CoreRuleSetMatcher;
use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;

final class BlocklistSection
{
    /** @var array<string, BlocklistRule> */
    private array $rules = [];

    /** @var array<string, PatternBackendInterface> */
    private array $patternBackends = [];

    /**
     * Add a closure-based blocklist rule.
     */
    public function add(string $name, Closure $callback): self
    {
        return $this->addRule(new BlocklistRule($name, new ClosureRequestMatcher($callback)));
    }

    /**
     * Add a typed blocklist rule with any RequestMatcherInterface.
     */
    public function addRule(BlocklistRule $blocklistRule): self
    {
        $this->rules[$blocklistRule->name()] = $blocklistRule;
        return $this;
    }

    /**
     * Register an OWASP Core Rule Set as a blocklist matcher.
     */
    public function owasp(string $name, CoreRuleSet $coreRuleSet): self
    {
        return $this->addRule(new BlocklistRule($name, new CoreRuleSetMatcher($coreRuleSet)));
    }

    /**
     * Block requests from known attack tools and vulnerability scanners by User-Agent.
     *
     * @param list<string>|null $patterns UA substrings to block. Defaults to KnownScannerMatcher::DEFAULT_PATTERNS.
     */
    public function knownScanners(string $name = 'known-scanners', ?array $patterns = null): self
    {
        return $this->addRule(new BlocklistRule($name, new KnownScannerMatcher($patterns)));
    }

    /**
     * Block requests whose client IP appears in a file-backed list.
     */
    public function fileIp(string $name, string $filePath, ?callable $ipResolver = null): FileIpBlocklistStore
    {
        $fileIpBlocklistStore = new FileIpBlocklistStore($filePath);
        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($filePath, $ipResolver);
        $this->addRule(new BlocklistRule($name, $fileIpBlocklistMatcher));
        return $fileIpBlocklistStore;
    }

    /**
     * Register a named pattern backend.
     */
    public function addPatternBackend(string $name, PatternBackendInterface $patternBackend): self
    {
        $this->patternBackends[$name] = $patternBackend;
        return $this;
    }

    /**
     * Create a blocklist rule backed by a registered pattern backend.
     */
    public function fromBackend(string $name, string $backendName): self
    {
        if (!isset($this->patternBackends[$backendName])) {
            throw new \InvalidArgumentException(sprintf('Pattern backend "%s" is not registered.', $backendName));
        }

        return $this->addRule(new BlocklistRule($name, new SnapshotBlocklistMatcher($this->patternBackends[$backendName])));
    }

    /**
     * Create a file-backed pattern backend and register it.
     */
    public function filePatternBackend(string $name, string $filePath): FilePatternBackend
    {
        $filePatternBackend = new FilePatternBackend($filePath);
        $this->addPatternBackend($name, $filePatternBackend);
        return $filePatternBackend;
    }

    /**
     * Create an in-memory pattern backend and register it.
     *
     * @param list<PatternEntry> $entries
     */
    public function inMemoryPatternBackend(string $name, array $entries = []): InMemoryPatternBackend
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend($entries);
        $this->addPatternBackend($name, $inMemoryPatternBackend);
        return $inMemoryPatternBackend;
    }

    /**
     * Create an in-memory pattern blocklist in one step.
     *
     * @param list<PatternEntry> $entries
     */
    public function patternBlocklist(string $name, array $entries): InMemoryPatternBackend
    {
        $inMemoryPatternBackend = $this->inMemoryPatternBackend($name, $entries);
        $this->fromBackend($name, $name);
        return $inMemoryPatternBackend;
    }

    /**
     * Create a file-backed pattern blocklist in one step.
     */
    public function filePatternBlocklist(string $name, string $filePath): FilePatternBackend
    {
        $filePatternBackend = $this->filePatternBackend($name, $filePath);
        $this->fromBackend($name, $name);
        return $filePatternBackend;
    }

    /**
     * @return array<string, BlocklistRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /**
     * @return array<string, PatternBackendInterface>
     */
    public function patternBackends(): array
    {
        return $this->patternBackends;
    }
}
