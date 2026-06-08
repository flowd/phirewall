<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Section;

use Closure;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Psr\Http\Message\ServerRequestInterface;

final class ThrottleSection
{
    /** @var array<string, ThrottleRule> */
    private array $rules = [];

    /**
     * Add a throttle rule. Omit $key to key on the client IP (Config IP resolver, else REMOTE_ADDR).
     *
     * @param int|Closure(ServerRequestInterface): int $limit
     * @param int|Closure(ServerRequestInterface): int $period
     * @param (Closure(ServerRequestInterface): ?string)|null $key
     */
    public function add(string $name, int|Closure $limit, int|Closure $period, ?Closure $key = null): self
    {
        return $this->addRule(new ThrottleRule($name, $limit, $period, $key instanceof Closure ? new ClosureKeyExtractor($key) : null));
    }

    /**
     * Add a sliding-window throttle rule.
     *
     * Unlike fixed-window throttling, the sliding window uses a weighted
     * average of the current and previous window counters to prevent the
     * "double burst" problem at window boundaries.
     *
     * When $key is omitted it defaults to the client IP (see {@see add()}).
     *
     * @param int|Closure(ServerRequestInterface): int $limit
     * @param int|Closure(ServerRequestInterface): int $period
     * @param (Closure(ServerRequestInterface): ?string)|null $key
     */
    public function sliding(string $name, int|Closure $limit, int|Closure $period, ?Closure $key = null): self
    {
        return $this->addRule(new ThrottleRule($name, $limit, $period, $key instanceof Closure ? new ClosureKeyExtractor($key) : null, sliding: true));
    }

    /**
     * Register multiple throttle windows under a single logical name.
     *
     * Each entry in $windowLimits maps a period (seconds) to a request limit.
     * A sub-rule is created for each window, named "{$name}:{$period}s".
     *
     * Example: $config->throttles->multi('api', [1 => 3, 60 => 100], $key)
     *   → creates "api:1s" (3 req/s burst) and "api:60s" (100 req/min sustained).
     *
     * When $key is omitted it defaults to the client IP (see {@see add()}).
     *
     * @param array<int, int> $windowLimits Map of period (seconds) => limit (max requests)
     * @param (Closure(ServerRequestInterface): ?string)|null $key
     */
    public function multi(string $name, array $windowLimits, ?Closure $key = null): self
    {
        if ($windowLimits === []) {
            throw new \InvalidArgumentException(
                sprintf('multiThrottle "%s": windowLimits must not be empty', $name)
            );
        }

        // Ensure deterministic evaluation order: shortest period (burst) first.
        ksort($windowLimits);

        foreach ($windowLimits as $period => $limit) {
            if ($period < 1) {
                throw new \InvalidArgumentException(
                    sprintf('multiThrottle "%s": period must be >= 1, got %d', $name, $period)
                );
            }

            if ($limit < 0) {
                throw new \InvalidArgumentException(
                    sprintf('multiThrottle "%s": limit must be non-negative, got %d for period %d', $name, $limit, $period)
                );
            }

            $this->add($name . ':' . $period . 's', $limit, $period, $key);
        }

        return $this;
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
