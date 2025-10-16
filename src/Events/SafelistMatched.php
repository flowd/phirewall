<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final class SafelistMatched
{
    public function __construct(
        public readonly string $rule,
        public readonly ServerRequestInterface $request,
    ) {
    }
}
