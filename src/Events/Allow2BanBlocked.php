<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Dispatched when a request is blocked because its key is already banned by an
 * allow2ban rule ({@see \Flowd\Phirewall\Http\DecisionPath::Allow2BanBlocked}).
 * Fires on every request of a banned key, regardless of the rule's filter.
 */
final readonly class Allow2BanBlocked
{
    public function __construct(
        public string $rule,
        public string $key,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
