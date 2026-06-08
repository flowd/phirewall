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
     * Add an allow2ban rule. Omit $key to key on the client IP (Config IP resolver, else REMOTE_ADDR).
     *
     * @param (Closure(\Psr\Http\Message\ServerRequestInterface): ?string)|null $key
     */
    public function add(string $name, int $threshold, int $period, int $banSeconds, ?Closure $key = null): self
    {
        return $this->addRule(new Allow2BanRule(
            $name,
            $threshold,
            $period,
            $banSeconds,
            $key instanceof Closure ? new ClosureKeyExtractor($key) : null,
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
