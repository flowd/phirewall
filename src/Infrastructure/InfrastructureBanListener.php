<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Optional PSR-14 event listener that mirrors application-level blocking
 * to an infrastructure adapter (e.g., Apache .htaccess).
 *
 * The listener schedules adapter calls using a NonBlockingRunner, so it
 * does not block request processing.
 */
final class InfrastructureBanListener
{
    /** @var callable(string):?string */
    private $keyToIp;

    /** @var callable(ServerRequestInterface):?string */
    private $requestToIp;

    public function __construct(
        private readonly InfrastructureBlockerInterface $infrastructureBlocker,
        private readonly NonBlockingRunnerInterface $nonBlockingRunner,
        /** If true, call adapter on Fail2Ban bans (default true). */
        private readonly bool $blockOnFail2Ban = true,
        /** If true, call adapter on Blocklist matches using request IP (default false). */
        private readonly bool $blockOnBlocklist = false,
        /**
         * Map a rule key (e.g., Fail2Ban key) to an IP address string or null to skip.
         * Defaults to identity (assumes key is already an IP address).
         * @param callable(string):?string $keyToIp
         */
        ?callable $keyToIp = null,
        /**
         * Extract IP address from a ServerRequestInterface. Defaults to REMOTE_ADDR.
         * @param callable(ServerRequestInterface):?string $requestToIp
         */
        ?callable $requestToIp = null,
    ) {
        $this->keyToIp = $keyToIp ?? static fn(string $key): string => $key;
        $this->requestToIp = $requestToIp ?? static function (ServerRequestInterface $serverRequest): ?string {
            $params = $serverRequest->getServerParams();
            $ip = $params['REMOTE_ADDR'] ?? null;
            return is_string($ip) ? $ip : null;
        };
    }

    /** Listener for Fail2Ban bans. */
    public function onFail2BanBanned(Fail2BanBanned $fail2BanBanned): void
    {
        if (!$this->blockOnFail2Ban) {
            return;
        }

        $ip = ($this->keyToIp)($fail2BanBanned->key);
        if (!is_string($ip) || $ip === '') {
            return; // cannot map to IP; skip
        }

        $this->nonBlockingRunner->run(function () use ($ip): void {
            try {
                $this->infrastructureBlocker->blockIp($ip);
            } catch (\Throwable) {
                // Intentionally swallow to keep non-blocking semantics
            }
        });
    }

    /** Listener for Blocklist matches. */
    public function onBlocklistMatched(BlocklistMatched $blocklistMatched): void
    {
        if (!$this->blockOnBlocklist) {
            return;
        }

        $ip = ($this->requestToIp)($blocklistMatched->serverRequest);
        if (!is_string($ip) || $ip === '') {
            return;
        }

        $this->nonBlockingRunner->run(function () use ($ip): void {
            try {
                $this->infrastructureBlocker->blockIp($ip);
            } catch (\Throwable) {
                // swallow
            }
        });
    }
}
