<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\DecisionPath;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * PSR-14 event listener that counts firewall decisions for testing and observability.
 *
 * Register as an event dispatcher to collect diagnostics:
 *
 *   $diagnostics = new DiagnosticsCounters();
 *   $config = new Config($cache, $diagnostics);
 *   // ... run firewall ...
 *   $diagnostics->all(); // ['safelisted' => ['total' => 1, 'by_rule' => ['health' => 1]], ...]
 *
 * Categories tracked: safelisted, blocklisted, throttled, fail2ban_banned, track_hit, passed,
 * fail2ban_blocked (via PerformanceMeasured).
 */
final class DiagnosticsCounters implements EventDispatcherInterface
{
    /**
     * @var array<string, array{total:int, by_rule: array<string,int> }>
     */
    private array $counters = [];

    private int $maxRulesPerCategory = 100;

    public function dispatch(object $event): object
    {
        match (true) {
            $event instanceof SafelistMatched => $this->increment('safelisted', $event->rule),
            $event instanceof BlocklistMatched => $this->increment('blocklisted', $event->rule),
            $event instanceof ThrottleExceeded => $this->increment('throttle_exceeded', $event->rule),
            $event instanceof Fail2BanBanned => $this->increment('fail2ban_banned', $event->rule),
            $event instanceof TrackHit => $this->increment('track_hit', $event->rule),
            $event instanceof PerformanceMeasured => $this->handlePerformanceMeasured($event),
            default => null,
        };

        return $event;
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
