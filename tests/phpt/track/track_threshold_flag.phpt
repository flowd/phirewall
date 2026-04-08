--TEST--
Phirewall: track dispatches TrackHit events and sets thresholdReached once limit is reached
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Psr\EventDispatcher\EventDispatcherInterface;

class CollectingDispatcher implements EventDispatcherInterface
{
    /** @var list<object> */
    public array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;
        return $event;
    }
}

$clock      = new FakeClock();
$dispatcher = new CollectingDispatcher();
$config     = new Config(new InMemoryCache($clock), $dispatcher);
$config->tracks->add(
    'api',
    period: 60,
    filter: fn() => true,
    key: KeyExtractors::ip(),
    limit: 3,
);

$middleware = phpt_middleware($config);
$handler    = phpt_handler();

// Five requests: track never blocks, all return 200.
for ($index = 1; $index <= 5; $index++) {
    $request  = phpt_request('GET', '/api', ['REMOTE_ADDR' => '1.2.3.4']);
    $response = $middleware->process($request, $handler);
    echo 'status[' . $index . ']=' . $response->getStatusCode() . "\n";
}

// Collect only TrackHit events (the dispatcher also receives PerformanceMeasured events).
$trackHits = array_values(
    array_filter($dispatcher->events, fn($event) => $event instanceof TrackHit)
);

echo 'event_count=' . count($trackHits) . "\n";

foreach ($trackHits as $eventIndex => $event) {
    $thresholdLabel = $event->thresholdReached ? 'true' : 'false';
    echo 'event[' . ($eventIndex + 1) . '].count=' . $event->count . ' threshold=' . $thresholdLabel . "\n";
}
?>
--EXPECT--
status[1]=200
status[2]=200
status[3]=200
status[4]=200
status[5]=200
event_count=5
event[1].count=1 threshold=false
event[2].count=2 threshold=false
event[3].count=3 threshold=true
event[4].count=4 threshold=true
event[5].count=5 threshold=true
