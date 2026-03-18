<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\SafelistRule;

final class SafelistSection
{
    /** @var array<string, SafelistRule> */
    private array $rules = [];

    /**
     * Add a closure-based safelist rule.
     */
    public function add(string $name, Closure $callback): self
    {
        return $this->addRule(new SafelistRule($name, new ClosureRequestMatcher($callback)));
    }

    /**
     * Add a typed safelist rule with any RequestMatcherInterface.
     */
    public function addRule(SafelistRule $safelistRule): self
    {
        $this->rules[$safelistRule->name()] = $safelistRule;
        return $this;
    }

    /**
     * @return array<string, SafelistRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
