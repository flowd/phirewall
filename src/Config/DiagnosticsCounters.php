<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\DecisionPath;

/**
 * Lightweight in-memory counters that observe firewall events for testing and observability.
 *
 * Use with DiagnosticsDispatcher to both count and forward events:
 *
 *   $counters = new DiagnosticsCounters();
 *   $dispatcher = new DiagnosticsDispatcher($counters, $realDispatcher);
 *   $config = new \Flowd\Phirewall\Config($cache, $dispatcher);
 *   // ... run firewall ...
 *   $counters->all(); // ['safelisted' => ['total' => 1, 'by_rule' => ['health' => 1]], ...]
 *
 * Categories tracked: safelisted, blocklisted, throttle_exceeded, fail2ban_banned, allow2ban_banned, track_hit, passed,
 * fail2ban_blocked (via PerformanceMeasured).
 */
final class DiagnosticsCounters
{
    /**
     * @var array<string, array{total:int, by_rule: array<string,int> }>
     */
    private array $counters = [];

    private int $maxRulesPerCategory = 100;

    public function observe(object $event): void
    {
        match (true) {
            $event instanceof SafelistMatched => $this->increment('safelisted', $event->rule),
            $event instanceof BlocklistMatched => $this->increment('blocklisted', $event->rule),
            $event instanceof ThrottleExceeded => $this->increment('throttle_exceeded', $event->rule),
            $event instanceof Fail2BanBanned => $this->increment('fail2ban_banned', $event->rule),
            $event instanceof Allow2BanBanned => $this->increment('allow2ban_banned', $event->rule),
            $event instanceof TrackHit => $this->increment('track_hit', $event->rule),
            $event instanceof PerformanceMeasured => $this->handlePerformanceMeasured($event),
            default => null,
        };
    }

    public function increment(string $category, ?string $rule = null): void
    {
        if (!isset($this->counters[$category])) {
            $this->counters[$category] = ['total' => 0, 'by_rule' => []];
        }

        ++$this->counters[$category]['total'];
        if ($rule !== null) {
            $byRule = & $this->counters[$category]['by_rule'];

            if (!array_key_exists($rule, $byRule)) {
                if (count($byRule) >= $this->maxRulesPerCategory) {
                    return;
                }

                $byRule[$rule] = 0;
            }

            ++$byRule[$rule];
        }
    }

    public function reset(): void
    {
        $this->counters = [];
    }

    /**
     * @return array<string, array{total:int, by_rule: array<string,int> }>
     */
    public function all(): array
    {
        return $this->counters;
    }

    private function handlePerformanceMeasured(PerformanceMeasured $performanceMeasured): void
    {
        // PerformanceMeasured fires for every decision — use it for paths
        // that don't have dedicated events (passed, fail2ban_blocked)
        if ($performanceMeasured->decisionPath === DecisionPath::Passed || $performanceMeasured->decisionPath === DecisionPath::Fail2BanBlocked) {
            $this->increment($performanceMeasured->decisionPath->value, $performanceMeasured->ruleName);
        }
    }
}
