<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistStore;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Matchers\SuspiciousHeadersMatcher;
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

    public function __construct(private readonly ?Config $config = null)
    {
    }

    public function add(string $name, Closure $callback): self
    {
        return $this->addRule(new BlocklistRule($name, new ClosureRequestMatcher($callback)));
    }

    public function addRule(BlocklistRule $blocklistRule): self
    {
        $this->rules[$blocklistRule->name()] = $blocklistRule;
        return $this;
    }

    public function owasp(string $name, CoreRuleSet $coreRuleSet): self
    {
        return $this->addRule(new BlocklistRule($name, new CoreRuleSetMatcher($coreRuleSet)));
    }

    /**
     * @param list<string>|null $patterns UA substrings to block. Defaults to KnownScannerMatcher::DEFAULT_PATTERNS.
     */
    public function knownScanners(string $name = 'known-scanners', ?array $patterns = null): self
    {
        return $this->addRule(new BlocklistRule($name, new KnownScannerMatcher($patterns)));
    }

    /**
     * Block requests whose client IP appears in a file-backed list.
     *
     * @param (callable(\Psr\Http\Message\ServerRequestInterface): ?string)|null $ipResolver Overrides Config's global IP resolver.
     */
    public function fileIp(string $name, string $filePath, ?callable $ipResolver = null): FileIpBlocklistStore
    {
        $resolver = $ipResolver ?? $this->config?->getIpResolver();
        $fileIpBlocklistStore = new FileIpBlocklistStore($filePath);
        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($filePath, $resolver);
        $this->addRule(new BlocklistRule($name, $fileIpBlocklistMatcher));
        return $fileIpBlocklistStore;
    }

    /**
     * Block requests missing standard HTTP headers that real browsers typically send.
     *
     * @param list<string> $requiredHeaders Headers that must be present. Empty = defaults (Accept, Accept-Language, Accept-Encoding).
     */
    public function suspiciousHeaders(string $name = 'suspicious-headers', array $requiredHeaders = []): self
    {
        return $this->addRule(new BlocklistRule($name, new SuspiciousHeadersMatcher($requiredHeaders)));
    }

    /**
     * Block requests from specific IPs or CIDR ranges.
     *
     * @param string|list<string> $ipOrCidr Single IP/CIDR or list of IPs/CIDRs.
     * @param (callable(\Psr\Http\Message\ServerRequestInterface): ?string)|null $ipResolver Overrides Config's global IP resolver.
     */
    public function ip(string $name, string|array $ipOrCidr, ?callable $ipResolver = null): self
    {
        $resolver = $ipResolver ?? $this->config?->getIpResolver();
        $ips = is_array($ipOrCidr) ? $ipOrCidr : [$ipOrCidr];
        return $this->addRule(new BlocklistRule($name, new IpMatcher($ips, $resolver)));
    }

    public function addPatternBackend(string $name, PatternBackendInterface $patternBackend): self
    {
        $this->patternBackends[$name] = $patternBackend;
        return $this;
    }

    public function fromBackend(string $name, string $backendName): self
    {
        if (!isset($this->patternBackends[$backendName])) {
            throw new \InvalidArgumentException(sprintf('Pattern backend "%s" is not registered.', $backendName));
        }

        $resolver = $this->config?->getIpResolver();
        return $this->addRule(new BlocklistRule($name, new SnapshotBlocklistMatcher($this->patternBackends[$backendName], $resolver)));
    }

    public function filePatternBackend(string $name, string $filePath): FilePatternBackend
    {
        $filePatternBackend = new FilePatternBackend($filePath);
        $this->addPatternBackend($name, $filePatternBackend);
        return $filePatternBackend;
    }

    /**
     * @param list<PatternEntry> $entries
     */
    public function inMemoryPatternBackend(string $name, array $entries = []): InMemoryPatternBackend
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend($entries);
        $this->addPatternBackend($name, $inMemoryPatternBackend);
        return $inMemoryPatternBackend;
    }

    /**
     * @param list<PatternEntry> $entries
     */
    public function patternBlocklist(string $name, array $entries): InMemoryPatternBackend
    {
        $inMemoryPatternBackend = $this->inMemoryPatternBackend($name, $entries);
        $this->fromBackend($name, $name);
        return $inMemoryPatternBackend;
    }

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
