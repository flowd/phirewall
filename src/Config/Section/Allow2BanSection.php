<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;

final class Allow2BanSection
{
    /** @var array<string, Allow2BanRule> */
    private array $rules = [];

    /**
     * Add an allow2ban rule with a closure key extractor.
     */
    public function add(string $name, int $threshold, int $period, int $banSeconds, Closure $key): self
    {
        return $this->addRule(new Allow2BanRule(
            $name,
            $threshold,
            $period,
            $banSeconds,
            new ClosureKeyExtractor($key),
        ));
    }

    /**
     * Add a typed Allow2BanRule directly.
     */
    public function addRule(Allow2BanRule $allow2BanRule): self
    {
        $this->rules[$allow2BanRule->name()] = $allow2BanRule;
        return $this;
    }

    /**
     * @return array<string, Allow2BanRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
