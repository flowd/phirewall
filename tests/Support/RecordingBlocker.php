<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Infrastructure\InfrastructureBlockerInterface;

final class RecordingBlocker implements InfrastructureBlockerInterface
{
    /** @var list<array{op:string, ip:string}> */
    public array $calls = [];

    public function blockIp(string $ipAddress): void
    {
        $this->calls[] = ['op' => 'block', 'ip' => $ipAddress];
    }

    public function unblockIp(string $ipAddress): void
    {
        $this->calls[] = ['op' => 'unblock', 'ip' => $ipAddress];
    }

    public function isBlocked(string $ipAddress): bool
    {
        // Check the calls in reverse order to find the latest operation for the given IP
        foreach (array_reverse($this->calls) as $call) {
            if ($call['ip'] === $ipAddress && $call['op'] === 'block') {
                return true;
            }

            if ($call['ip'] === $ipAddress && $call['op'] === 'unblock') {
                return false;
            }
        }

        return false;
    }
}
