<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;
use Flowd\Phirewall\Config\RequestMatcherInterface;

/**
 * Allow2Ban rule: lets matching requests through until a threshold is crossed within a
 * time window, then bans the key for a configurable duration.
 *
 * Like Fail2Ban it counts filter matches, but unlike Fail2Ban it lets matching requests
 * pass until the threshold is reached instead of blocking each match. A null filter
 * matches every request, which is the classic hard volume cap.
 */
final readonly class Allow2BanRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private int $threshold,
        private int $period,
        private int $banSeconds,
        private ?KeyExtractorInterface $keyExtractor,
        private ?RequestMatcherInterface $requestMatcher = null,
    ) {
        if ($name === '') {
            throw new \InvalidArgumentException('Allow2BanRule name must not be empty.');
        }

        if ($threshold < 1) {
            throw new \InvalidArgumentException(sprintf('Allow2BanRule threshold must be >= 1, got %d.', $threshold));
        }

        if ($period < 1) {
            throw new \InvalidArgumentException(sprintf('Allow2BanRule period must be >= 1, got %d.', $period));
        }

        if ($banSeconds < 1) {
            throw new \InvalidArgumentException(sprintf('Allow2BanRule banSeconds must be >= 1, got %d.', $banSeconds));
        }
    }

    public function name(): string
    {
        return $this->name;
    }

    public function threshold(): int
    {
        return $this->threshold;
    }

    public function period(): int
    {
        return $this->period;
    }

    public function banSeconds(): int
    {
        return $this->banSeconds;
    }

    /** Null when no key was specified; defaults to the client IP at evaluation. */
    public function keyExtractor(): ?KeyExtractorInterface
    {
        return $this->keyExtractor;
    }

    /** Null when no filter was specified; the rule then counts every request. */
    public function filter(): ?RequestMatcherInterface
    {
        return $this->requestMatcher;
    }
}
