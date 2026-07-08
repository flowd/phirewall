<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Dispatched when a fail2ban filter matches a request that is blocked below the
 * ban threshold. The Nth (threshold) match dispatches {@see Fail2BanBanned}
 * instead, never both.
 */
final readonly class Fail2BanMatched
{
    public function __construct(
        public string $rule,
        public string $key,
        public int $threshold,
        public int $period,
        public int $count,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
