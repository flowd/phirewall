<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Dispatched when the firewall encounters an error during request evaluation.
 *
 * This event is only dispatched in fail-open mode (the default). Listeners
 * should log the error for monitoring and alerting. The request is allowed
 * through to prevent a cache/storage outage from taking down the application.
 */
final readonly class FirewallError
{
    public function __construct(
        public \Throwable $exception,
        public ServerRequestInterface $serverRequest,
    ) {
    }
}
