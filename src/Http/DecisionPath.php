<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

/**
 * Enumerates all possible decision paths the firewall can take during request evaluation.
 *
 * Each case corresponds to a specific outcome in the firewall pipeline.
 * The string backing value is used for diagnostics counters and performance events.
 */
enum DecisionPath: string
{
    case Passed = 'passed';
    case Safelisted = 'safelisted';
    case Blocklisted = 'blocklisted';
    case Fail2BanBlocked = 'fail2ban_blocked';
    case Fail2BanBanned = 'fail2ban_banned';
    case Throttled = 'throttled';
    case Allow2BanBlocked = 'allow2ban_blocked';
    case Allow2BanBanned = 'allow2ban_banned';
}
