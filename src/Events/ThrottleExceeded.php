<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final class ThrottleExceeded
{
    public function __construct(
        public readonly string $rule,
        public readonly string $key,
        public readonly int $limit,
        public readonly int $period,
        public readonly int $count,
        public readonly int $retryAfter,
        public readonly ServerRequestInterface $request,
    ) {
    }
}
