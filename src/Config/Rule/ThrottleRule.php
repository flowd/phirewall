<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

use Flowd\Phirewall\Config\KeyExtractorInterface;

final readonly class ThrottleRule implements RuleInterface
{
    public function __construct(
        private string $name,
        private int $limit,
        private int $period,
        private KeyExtractorInterface $keyExtractor,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function limit(): int
    {
        return $this->limit;
    }

    public function period(): int
    {
        return $this->period;
    }

    public function keyExtractor(): KeyExtractorInterface
    {
        return $this->keyExtractor;
    }
}
