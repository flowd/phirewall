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
     * Add a track rule. Omit $key to key on the client IP (Config IP resolver, else REMOTE_ADDR).
     * When $limit is set, TrackHit carries a thresholdReached flag once the count reaches it.
     *
     * @param Closure(\Psr\Http\Message\ServerRequestInterface): bool $filter
     * @param (Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null $key
     */
    public function add(string $name, int $period, Closure $filter, ?Closure $key = null, ?int $limit = null): self
    {
        return $this->addRule(new TrackRule($name, $period, new ClosureRequestMatcher($filter), $key instanceof Closure ? new ClosureKeyExtractor($key) : null, $limit));
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
