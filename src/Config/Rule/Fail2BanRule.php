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
