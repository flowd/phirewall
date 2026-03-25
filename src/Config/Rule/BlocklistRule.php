<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\RequestMatcherInterface;

final readonly class BlocklistRule implements RuleInterface
{
    /**
     * @param string $name Unique rule identifier
     * @param RequestMatcherInterface $requestMatcher Filter to decide which requests match this blocklist rule
     *
     * @throws \InvalidArgumentException If name is empty
     */
    public function __construct(
        private string $name,
        private RequestMatcherInterface $requestMatcher,
    ) {
        if ($this->name === '') {
            throw new \InvalidArgumentException('BlocklistRule name must not be empty.');
        }
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
