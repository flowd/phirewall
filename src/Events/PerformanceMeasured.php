<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Flowd\Phirewall\Http\DecisionPath;

final readonly class PerformanceMeasured
{
    public function __construct(
        public DecisionPath $decisionPath,
        public int $durationMicros,
        public ?string $ruleName = null,
    ) {
    }
}
