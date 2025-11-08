<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final readonly class TrackHit
{
    public function __construct(
        public string $rule,
        public string $key,
        public int $period,
        public int $count,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
