<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;

final class SafelistSection
{
    /** @var array<string, SafelistRule> */
    private array $rules = [];

    public function __construct(private readonly ?Config $config = null)
    {
    }

    public function add(string $name, Closure $callback): self
    {
        return $this->addRule(new SafelistRule($name, new ClosureRequestMatcher($callback)));
    }

    public function addRule(SafelistRule $safelistRule): self
    {
        $this->rules[$safelistRule->name()] = $safelistRule;
        return $this;
    }

    /**
     * Safelist verified search engine bots via reverse DNS verification.
     *
     * @param list<array{ua: string, hostname: string}> $additionalBots Extra bots to recognize.
     * @param (callable(\Psr\Http\Message\ServerRequestInterface): ?string)|null $ipResolver Overrides Config's global IP resolver for this matcher.
     * @param \Psr\SimpleCache\CacheInterface|null $cache PSR-16 cache for DNS results (avoids repeated lookups).
     */
    public function trustedBots(string $name = 'trusted-bots', array $additionalBots = [], ?callable $ipResolver = null, ?\Psr\SimpleCache\CacheInterface $cache = null): self
    {
        $resolver = $ipResolver ?? $this->config?->getIpResolver();
        return $this->addRule(new SafelistRule($name, new TrustedBotMatcher($additionalBots, ipResolver: $resolver, cache: $cache)));
    }

    /**
     * Safelist requests from specific IPs or CIDR ranges.
     *
     * @param string|list<string> $ipOrCidr Single IP/CIDR or list of IPs/CIDRs.
     * @param (callable(\Psr\Http\Message\ServerRequestInterface): ?string)|null $ipResolver Overrides Config's global IP resolver for this matcher.
     */
    public function ip(string $name, string|array $ipOrCidr, ?callable $ipResolver = null): self
    {
        $resolver = $ipResolver ?? $this->config?->getIpResolver();
        $ips = is_array($ipOrCidr) ? $ipOrCidr : [$ipOrCidr];
        return $this->addRule(new SafelistRule($name, new IpMatcher($ips, $resolver)));
    }

    /**
     * @return array<string, SafelistRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
