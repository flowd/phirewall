<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;
use Flowd\Phirewall\Config\RequestMatcherInterface;

final readonly class TrackRule implements RuleInterface
{
    /**
     * @param string $name Unique rule identifier
     * @param int $period Time window in seconds for counting
     * @param RequestMatcherInterface $requestMatcher Filter to decide which requests to count
     * @param KeyExtractorInterface $keyExtractor Extracts the grouping key from the request
     * @param int|null $limit Optional threshold; when set, TrackHit events include thresholdReached=true once count >= limit
     *
     * @throws \InvalidArgumentException If limit is non-null and less than 1
     */
    public function __construct(
        private string $name,
        private int $period,
        private RequestMatcherInterface $requestMatcher,
        private KeyExtractorInterface $keyExtractor,
        private ?int $limit = null,
    ) {
        if ($this->limit !== null && $this->limit < 1) {
            throw new \InvalidArgumentException(
                sprintf('Track rule "%s" limit must be at least 1, got %d.', $this->name, $this->limit)
            );
        }
    }

    public function name(): string
    {
        return $this->name;
    }

    public function period(): int
    {
        return $this->period;
    }

    public function filter(): RequestMatcherInterface
    {
        return $this->requestMatcher;
    }

    public function keyExtractor(): KeyExtractorInterface
    {
        return $this->keyExtractor;
    }

    public function limit(): ?int
    {
        return $this->limit;
    }
}
