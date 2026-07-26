<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Flowd\Phirewall\Config\MatchResult;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ThrottleExceeded
{
    /** @param MatchResult|null $matchResult Scope-filter match; null for unscoped throttles. */
    public function __construct(
        public string $rule,
        public string $key,
        public int $limit,
        public int $period,
        public int $count,
        public int $retryAfter,
        public ServerRequestInterface $serverRequest,
        public ?MatchResult $matchResult,
    ) {
    }
}
