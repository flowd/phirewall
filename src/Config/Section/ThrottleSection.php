<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\Rule\ThrottleRule;

final class ThrottleSection
{
    /** @var array<string, ThrottleRule> */
    private array $rules = [];

    /**
     * Add a throttle rule with a closure key extractor.
     */
    public function add(string $name, int $limit, int $period, Closure $key): self
    {
        return $this->addRule(new ThrottleRule($name, $limit, $period, new ClosureKeyExtractor($key)));
    }

    /**
     * Add a typed ThrottleRule directly.
     */
    public function addRule(ThrottleRule $throttleRule): self
    {
        $this->rules[$throttleRule->name()] = $throttleRule;
        return $this;
    }

    /**
     * @return array<string, ThrottleRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
