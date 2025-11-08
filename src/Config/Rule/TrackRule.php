<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;
use Flowd\Phirewall\Config\RequestMatcherInterface;

final readonly class TrackRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private int $period,
        private RequestMatcherInterface $requestMatcher,
        private KeyExtractorInterface $keyExtractor,
    ) {
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
}
