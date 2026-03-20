<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

enum BanType: string
{
    case Allow2Ban = 'allow2ban';
    case Fail2Ban = 'fail2ban';
}
