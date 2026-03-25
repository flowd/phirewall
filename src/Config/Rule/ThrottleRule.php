<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Closure;
use Flowd\Phirewall\Config\KeyExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ThrottleRule implements RuleInterface
{
    /**
     * @param int|Closure(ServerRequestInterface): int $limit Maximum number of requests allowed in the period
     * @param int|Closure(ServerRequestInterface): int $period Time window in seconds
     */
    public function __construct(
        private string $name,
        private int|Closure $limit,
        private int|Closure $period,
        private KeyExtractorInterface $keyExtractor,
        private bool $sliding = false,
    ) {
        if ($this->name === '') {
            throw new \InvalidArgumentException('ThrottleRule name must not be empty.');
        }

        if (is_int($this->limit) && $this->limit < 0) {
            throw new \InvalidArgumentException(
                sprintf('ThrottleRule "%s": static limit must be non-negative, got %d', $this->name, $this->limit)
            );
        }

        if (is_int($this->period) && $this->period < 1) {
            throw new \InvalidArgumentException(
                sprintf('ThrottleRule "%s": static period must be >= 1, got %d', $this->name, $this->period)
            );
        }
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * @return int|Closure(ServerRequestInterface): int
     */
    public function limit(): int|Closure
    {
        return $this->limit;
    }

    /**
     * @return int|Closure(ServerRequestInterface): int
     */
    public function period(): int|Closure
    {
        return $this->period;
    }

    /**
     * Resolve the limit for a specific request.
     * When the limit is a closure, it is invoked with the request to determine the dynamic limit.
     */
    public function resolveLimit(ServerRequestInterface $serverRequest): int
    {
        if ($this->limit instanceof Closure) {
            $resolved = ($this->limit)($serverRequest);
            if ($resolved < 0) {
                throw new \RuntimeException(
                    sprintf('ThrottleRule "%s": dynamic limit must be non-negative, got %d', $this->name, $resolved)
                );
            }

            return $resolved;
        }

        return $this->limit;
    }

    /**
     * Resolve the period for a specific request.
     * When the period is a closure, it is invoked with the request to determine the dynamic period.
     */
    public function resolvePeriod(ServerRequestInterface $serverRequest): int
    {
        if ($this->period instanceof Closure) {
            $resolved = ($this->period)($serverRequest);
            if ($resolved < 1) {
                throw new \RuntimeException(
                    sprintf('ThrottleRule "%s": dynamic period must be >= 1, got %d', $this->name, $resolved)
                );
            }

            return $resolved;
        }

        return $this->period;
    }

    public function keyExtractor(): KeyExtractorInterface
    {
        return $this->keyExtractor;
    }

    /**
     * Whether the period is a closure (resolved per request).
     */
    public function hasDynamicPeriod(): bool
    {
        return $this->period instanceof Closure;
    }

    /**
     * Whether this rule uses sliding window rate limiting.
     */
    public function isSliding(): bool
    {
        return $this->sliding;
    }
}
