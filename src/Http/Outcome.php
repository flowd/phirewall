<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

/**
 * Represents the outcome of a firewall decision.
 */
enum Outcome: string
{
    case PASS = 'pass';
    case SAFELISTED = 'safelisted';
    case BLOCKED = 'blocked';
    case THROTTLED = 'throttled';
}
