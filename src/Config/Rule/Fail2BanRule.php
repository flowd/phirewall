<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;
use Flowd\Phirewall\Config\RequestMatcherInterface;

final readonly class Fail2BanRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private int $threshold,
        private int $period,
        private int $banSeconds,
        private RequestMatcherInterface $requestMatcher,
        private KeyExtractorInterface $keyExtractor,
    ) {
        if ($name === '') {
            throw new \InvalidArgumentException('Fail2BanRule name must not be empty.');
        }

        if ($threshold < 1) {
            throw new \InvalidArgumentException(sprintf('Fail2BanRule threshold must be >= 1, got %d.', $threshold));
        }

        if ($period < 1) {
            throw new \InvalidArgumentException(sprintf('Fail2BanRule period must be >= 1, got %d.', $period));
        }

        if ($banSeconds < 1) {
            throw new \InvalidArgumentException(sprintf('Fail2BanRule banSeconds must be >= 1, got %d.', $banSeconds));
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

    public function filter(): RequestMatcherInterface
    {
        return $this->requestMatcher;
    }

    public function keyExtractor(): KeyExtractorInterface
    {
        return $this->keyExtractor;
    }
}
