<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

final readonly class PerformanceMeasured
{
    public function __construct(
        public string $decisionPath,
        public int $durationMicros,
        public ?string $ruleName = null,
    ) {
    }
}
