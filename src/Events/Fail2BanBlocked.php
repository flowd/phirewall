<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Dispatched when a request is blocked because its key is already banned by a
 * fail2ban rule ({@see \Flowd\Phirewall\Http\DecisionPath::Fail2BanBlocked}).
 * Fires on every request of a banned key.
 */
final readonly class Fail2BanBlocked
{
    public function __construct(
        public string $rule,
        public string $key,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
