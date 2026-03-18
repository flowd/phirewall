<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\TrackRule;

final class TrackSection
{
    /** @var array<string, TrackRule> */
    private array $rules = [];

    /**
     * Add a track rule with closure filter and key extractor.
     */
    public function add(string $name, int $period, Closure $filter, Closure $key): self
    {
        return $this->addRule(new TrackRule($name, $period, new ClosureRequestMatcher($filter), new ClosureKeyExtractor($key)));
    }

    /**
     * Add a typed TrackRule directly.
     */
    public function addRule(TrackRule $trackRule): self
    {
        $this->rules[$trackRule->name()] = $trackRule;
        return $this;
    }

    /**
     * @return array<string, TrackRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
