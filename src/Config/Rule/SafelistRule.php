<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\RequestMatcherInterface;

final readonly class SafelistRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private RequestMatcherInterface $requestMatcher,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function matcher(): RequestMatcherInterface
    {
        return $this->requestMatcher;
    }
}
