<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Context;

/**
 * Immutable value object representing a single fail2ban failure signal
 * recorded by application code via the RequestContext.
 */
final readonly class RecordedFailure
{
    public function __construct(
        public string $ruleName,
        public string $key,
    ) {
    }
}
