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
     * Add a fail2ban rule with closure filter and key extractor.
     */
    public function add(string $name, int $threshold, int $period, int $ban, Closure $filter, Closure $key): self
    {
        return $this->addRule(new Fail2BanRule(
            $name,
            $threshold,
            $period,
            $ban,
            new ClosureRequestMatcher($filter),
            new ClosureKeyExtractor($key),
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
