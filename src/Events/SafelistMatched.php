<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final readonly class SafelistMatched
{
    public function __construct(
        public string $rule,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
