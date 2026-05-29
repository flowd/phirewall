<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Context;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Http\FirewallResult;

/**
 * Mutable recorder attached to a PSR-7 request attribute.
 *
 * Application code retrieves this from the request after the firewall has
 * passed the request through and then signals post-handler events that
 * should be processed against fail2ban or allow2ban rules once the handler
 * returns:
 *
 *   - {@see recordFailure()} for fail2ban rules (a failure occurred)
 *   - {@see recordHit()} for allow2ban rules (a countable event occurred)
 *
 * Both methods take an optional `$key`: when omitted, the firewall reuses
 * the rule's own keyExtractor against the current request, so the handler
 * doesn't need to know whether the rule keys on IP, header, or anything
 * else.
 */
final class RequestContext
{
    public const ATTRIBUTE_NAME = 'phirewall.context';

    /** @var list<RecordedSignal> */
    private array $recordedSignals = [];

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
     * The ruleName must match a configured fail2ban rule. When `$key` is
     * null (the default), the firewall extracts the discriminator from the
     * rule's keyExtractor on the current request. Pass an explicit key only
     * when the handler knows a value the firewall cannot derive from the
     * request itself (e.g. a user id looked up from a session).
     */
    public function recordFailure(string $ruleName, ?string $key = null): void
    {
        $this->recordedSignals[] = new RecordedSignal($ruleName, BanType::Fail2Ban, $key);
    }

    /**
     * Record an allow2ban hit signal for post-handler processing.
     *
     * The ruleName must match a configured allow2ban rule. When `$key` is
     * null (the default), the firewall extracts the discriminator from the
     * rule's keyExtractor on the current request.
     *
     * Useful for counting handler-observable events that the pre-handler
     * path can't see — e.g. an expensive operation completed, a webhook
     * delivered a duplicate payload, a third-party API quota was charged.
     */
    public function recordHit(string $ruleName, ?string $key = null): void
    {
        $this->recordedSignals[] = new RecordedSignal($ruleName, BanType::Allow2Ban, $key);
    }

    /**
     * @return list<RecordedSignal>
     */
    public function getRecordedSignals(): array
    {
        return $this->recordedSignals;
    }

    /**
     * Whether any signals have been recorded by the handler.
     */
    public function hasRecordedSignals(): bool
    {
        return $this->recordedSignals !== [];
    }
}
