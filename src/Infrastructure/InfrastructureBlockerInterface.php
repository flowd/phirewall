<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

/**
 * Interface for pluggable infrastructure-level blockers (e.g., Apache, Nginx, WAF).
 *
 * Adapters should perform fast operations and avoid blocking request handling.
 * They may be invoked from a non-blocking executor.
 */
interface InfrastructureBlockerInterface
{
    /**
     * Add an IP address to the infrastructure-level block list.
     *
     * Implementations should be idempotent when called repeatedly with the same IP address.
     *
     * @throws \InvalidArgumentException if the IP address is invalid or unsupported
     * @throws \RuntimeException on I/O or environment errors
     */
    public function blockIp(string $ipAddress): void;

    /**
     * Remove an IP address from the infrastructure-level block list.
     *
     * Implementations should be idempotent when the IP address is not present.
     *
     * @throws \InvalidArgumentException if the IP address is invalid or unsupported
     * @throws \RuntimeException on I/O or environment errors
     */
    public function unblockIp(string $ipAddress): void;

    /**
     * Determine whether an IP address is currently blocked according to this adapter.
     *
     * Implementations may return false if the state cannot be reliably determined.
     *
     * @throws \InvalidArgumentException if the IP address is invalid or unsupported
     * @throws \RuntimeException on I/O or environment errors
     */
    public function isBlocked(string $ipAddress): bool;
}
