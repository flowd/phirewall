<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Context;

use Flowd\Phirewall\Http\FirewallResult;

/**
 * Mutable recorder attached to a PSR-7 request attribute.
 *
 * Application code retrieves this from the request after the firewall has
 * passed the request through, then calls recordFailure() to signal fail2ban
 * events that should be processed after the handler returns.
 */
final class RequestContext
{
    public const ATTRIBUTE_NAME = 'phirewall.context';

    /** @var list<RecordedFailure> */
    private array $recordedFailures = [];

    public function __construct(
        private readonly FirewallResult $result,
    ) {
    }

    public function getResult(): FirewallResult
    {
        return $this->result;
    }

    /**
     * Record a fail2ban failure signal for post-handler processing.
     *
     * The ruleName must match a configured fail2ban rule name.
     * The key is the discriminator (e.g. IP address, username).
     */
    public function recordFailure(string $ruleName, string $key): void
    {
        $this->recordedFailures[] = new RecordedFailure($ruleName, $key);
    }

    /**
     * @return list<RecordedFailure>
     */
    public function getRecordedFailures(): array
    {
        return $this->recordedFailures;
    }

    /**
     * Whether any failure signals have been recorded.
     */
    public function hasRecordedSignals(): bool
    {
        return $this->recordedFailures !== [];
    }
}
