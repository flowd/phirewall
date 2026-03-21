<?php

/**
 * Example 25: Track with Threshold (Limit)
 *
 * Demonstrates how to use the optional limit parameter on track rules.
 * TrackHit events always fire on every matching request. When a limit is
 * configured, the event includes a `thresholdReached` flag that becomes
 * true once count >= limit.
 *
 * This preserves full observability while letting consumers filter on the
 * flag for alerting only when suspicious activity exceeds a noise floor.
 *
 * Run: php examples/25-track-threshold.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;

echo "=== Track with Threshold Example ===\n\n";

// A simple event dispatcher that collects dispatched events for inspection.
$events = new class () implements EventDispatcherInterface {
    /** @var list<object> */
    public array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;
        return $event;
    }
};

$cache = new InMemoryCache();
$config = new Config($cache, $events);

// -----------------------------------------------------------------------------
// Track without limit -- fires on every match, thresholdReached is always false
// -----------------------------------------------------------------------------

$config->tracks->add(
    'every-login-attempt',
    period: 60,
    filter: fn($request): bool => $request->getUri()->getPath() === '/login',
    key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0',
);

// -----------------------------------------------------------------------------
// Track WITH limit -- fires on every match, thresholdReached=true at count >= 5
// -----------------------------------------------------------------------------

$config->tracks->add(
    'suspicious-login-burst',
    period: 60,
    filter: fn($request): bool => $request->getUri()->getPath() === '/login',
    key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0',
    limit: 5,
);

echo "Configured two track rules:\n";
echo "  1. 'every-login-attempt'    -- no limit (thresholdReached always false)\n";
echo "  2. 'suspicious-login-burst' -- limit=5  (thresholdReached=true at 5+ hits)\n\n";

// =============================================================================
// SIMULATION
// =============================================================================

$firewall = new Firewall($config);

echo "Sending 7 POST /login requests from 10.0.0.1 ...\n\n";

for ($i = 1; $i <= 7; ++$i) {
    $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
    $result = $firewall->decide($request);

    // Gather all TrackHit events fired so far
    $newHits = array_filter($events->events, fn(object $e): bool => $e instanceof TrackHit);

    echo sprintf(
        "  Request #%d -> %s | TrackHit events so far: %d\n",
        $i,
        $result->isPass() ? 'PASS' : 'BLOCKED',
        count($newHits),
    );
}

echo "\n";

// Show event summary
$trackHits = array_values(array_filter($events->events, fn(object $e): bool => $e instanceof TrackHit));
echo "=== TrackHit Events Summary ===\n";
foreach ($trackHits as $trackHit) {
    echo sprintf(
        "  rule=%-30s key=%-12s count=%d  period=%ds  limit=%s  thresholdReached=%s\n",
        $trackHit->rule,
        $trackHit->key,
        $trackHit->count,
        $trackHit->period,
        $trackHit->limit !== null ? (string) $trackHit->limit : 'none',
        $trackHit->thresholdReached ? 'YES' : 'no',
    );
}

echo "\nTotal TrackHit events: " . count($trackHits) . "\n";
echo "  'every-login-attempt' events:    " . count(array_filter($trackHits, fn(TrackHit $trackHit): bool => $trackHit->rule === 'every-login-attempt')) . " (expected: 7, all with thresholdReached=false)\n";
echo "  'suspicious-login-burst' events: " . count(array_filter($trackHits, fn(TrackHit $trackHit): bool => $trackHit->rule === 'suspicious-login-burst')) . " (expected: 7, thresholdReached=true at requests 5-7)\n";

$thresholdReachedCount = count(array_filter($trackHits, fn(TrackHit $trackHit): bool => $trackHit->thresholdReached));
echo "  Events with thresholdReached=true: {$thresholdReachedCount} (expected: 3)\n";

echo "\n=== Example Complete ===\n";
