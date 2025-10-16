<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final readonly class Fail2BanBanned
{
    public function __construct(
        public string $rule,
        public string $key,
        public int $threshold,
        public int $period,
        public int $banSeconds,
        public int $count,
        public ServerRequestInterface $request,
    ) {
    }
}
