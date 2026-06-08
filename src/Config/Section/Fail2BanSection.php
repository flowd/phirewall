<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;

final class Fail2BanSection
{
    /** @var array<string, Fail2BanRule> */
    private array $rules = [];

    /**
     * Add a fail2ban rule. Omit $key to key on the client IP (Config IP resolver, else REMOTE_ADDR).
     *
     * @param Closure(\Psr\Http\Message\ServerRequestInterface): bool $filter
     * @param (Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null $key
     */
    public function add(string $name, int $threshold, int $period, int $ban, Closure $filter, ?Closure $key = null): self
    {
        return $this->addRule(new Fail2BanRule(
            $name,
            $threshold,
            $period,
            $ban,
            new ClosureRequestMatcher($filter),
            $key instanceof Closure ? new ClosureKeyExtractor($key) : null,
        ));
    }

    /**
     * Add a typed Fail2BanRule directly.
     */
    public function addRule(Fail2BanRule $fail2BanRule): self
    {
        $this->rules[$fail2BanRule->name()] = $fail2BanRule;
        return $this;
    }

    /**
     * @return array<string, Fail2BanRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
