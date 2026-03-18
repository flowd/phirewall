<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;

/**
 * Allow2Ban rule: allows all requests until a threshold is crossed within a time window,
 * then bans the key for a configurable duration.
 *
 * This is the inverse of Fail2Ban -- instead of counting only filtered "bad" requests,
 * it counts every request for the extracted key and bans once the threshold is exceeded.
 */
final readonly class Allow2BanRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private int $threshold,
        private int $period,
        private int $banSeconds,
        private KeyExtractorInterface $keyExtractor,
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

    public function keyExtractor(): KeyExtractorInterface
    {
        return $this->keyExtractor;
    }
}
