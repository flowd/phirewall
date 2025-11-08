<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final readonly class ThrottleExceeded
{
    public function __construct(
        public string $rule,
        public string $key,
        public int $limit,
        public int $period,
        public int $count,
        public int $retryAfter,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
