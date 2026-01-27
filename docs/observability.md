# Observability & Events

Phirewall provides comprehensive observability through PSR-14 events and built-in diagnostics counters.

## Event System

### Enabling Events

Pass a PSR-14 EventDispatcher to the Config constructor:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = /* your PSR-14 dispatcher */;
$config = new Config(new InMemoryCache(), $dispatcher);
```

---

## Available Events

### SafelistMatched

Dispatched when a request matches a safelist rule and bypasses other checks.

```php
use Flowd\Phirewall\Events\SafelistMatched;

// Properties
$event->rule;           // string - Rule name
$event->serverRequest;  // ServerRequestInterface
```

### BlocklistMatched

Dispatched when a request matches a blocklist rule and is blocked.

```php
use Flowd\Phirewall\Events\BlocklistMatched;

// Properties
$event->rule;           // string - Rule name
$event->serverRequest;  // ServerRequestInterface
```

### ThrottleExceeded

Dispatched when a request exceeds a throttle limit.

```php
use Flowd\Phirewall\Events\ThrottleExceeded;

// Properties
$event->rule;           // string - Rule name
$event->key;            // string - Throttle key (e.g., IP)
$event->limit;          // int - Configured limit
$event->period;         // int - Window size in seconds
$event->count;          // int - Current request count
$event->retryAfter;     // int - Seconds until window resets
$event->serverRequest;  // ServerRequestInterface
```

### Fail2BanBanned

Dispatched when a key is banned by Fail2Ban.

```php
use Flowd\Phirewall\Events\Fail2BanBanned;

// Properties
$event->rule;           // string - Rule name
$event->key;            // string - Banned key (e.g., IP)
$event->threshold;      // int - Failures before ban
$event->period;         // int - Observation window
$event->banSeconds;     // int - Ban duration
$event->count;          // int - Failure count that triggered ban
$event->serverRequest;  // ServerRequestInterface
```

### TrackHit

Dispatched when a tracking rule matches (passive counting).

```php
use Flowd\Phirewall\Events\TrackHit;

// Properties
$event->rule;           // string - Rule name
$event->key;            // string - Track key
$event->period;         // int - Window size
$event->count;          // int - Current count
$event->serverRequest;  // ServerRequestInterface
```

### PerformanceMeasured

Dispatched after every firewall decision with timing information.

```php
use Flowd\Phirewall\Events\PerformanceMeasured;

// Properties
$event->decisionPath;   // string - 'passed', 'safelisted', 'blocklisted', 'throttled', etc.
$event->durationMicros; // int - Processing time in microseconds
$event->ruleName;       // ?string - Rule that decided (null if passed)
```

---

## Integration Examples

### Minimal Dispatcher

```php
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        error_log('[Firewall] ' . $event::class);
        return $event;
    }
};
```

### Monolog Integration

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Psr\EventDispatcher\EventDispatcherInterface;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;

$logger = new Logger('firewall');
$logger->pushHandler(new StreamHandler('/var/log/firewall.log', Logger::INFO));
$logger->pushHandler(new StreamHandler('/var/log/firewall-attacks.log', Logger::WARNING));

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    public function __construct(private Logger $logger) {}

    public function dispatch(object $event): object
    {
        $context = $this->extractContext($event);

        match (true) {
            $event instanceof BlocklistMatched => $this->logger->warning('Request blocked', $context),
            $event instanceof ThrottleExceeded => $this->logger->warning('Rate limit exceeded', $context),
            $event instanceof Fail2BanBanned => $this->logger->warning('IP banned', $context),
            default => $this->logger->info('Firewall event', $context),
        };

        return $event;
    }

    private function extractContext(object $event): array
    {
        $context = ['event' => $event::class];

        if (property_exists($event, 'rule')) {
            $context['rule'] = $event->rule;
        }
        if (property_exists($event, 'key')) {
            $context['key'] = $event->key;
        }
        if (property_exists($event, 'serverRequest')) {
            $request = $event->serverRequest;
            $context['method'] = $request->getMethod();
            $context['path'] = $request->getUri()->getPath();
            $context['ip'] = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        }

        return $context;
    }
};
```

### OpenTelemetry Integration

```php
use OpenTelemetry\API\Metrics\MeterInterface;
use OpenTelemetry\API\Trace\TracerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Flowd\Phirewall\Events\PerformanceMeasured;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;

$dispatcher = new class ($tracer, $meter) implements EventDispatcherInterface {
    private $eventCounter;
    private $latencyHistogram;

    public function __construct(
        private TracerInterface $tracer,
        private MeterInterface $meter
    ) {
        $this->eventCounter = $meter->createCounter(
            'phirewall.events',
            'count',
            'Firewall events by type'
        );
        $this->latencyHistogram = $meter->createHistogram(
            'phirewall.latency',
            'us',
            'Firewall decision latency'
        );
    }

    public function dispatch(object $event): object
    {
        $eventType = (new \ReflectionClass($event))->getShortName();

        // Count all events
        $this->eventCounter->add(1, ['type' => $eventType]);

        // Record latency for performance events
        if ($event instanceof PerformanceMeasured) {
            $this->latencyHistogram->record($event->durationMicros, [
                'decision' => $event->decisionPath,
                'rule' => $event->ruleName ?? 'none',
            ]);
        }

        // Create spans for blocking events
        if ($event instanceof BlocklistMatched ||
            $event instanceof ThrottleExceeded ||
            $event instanceof Fail2BanBanned) {
            $span = $this->tracer->spanBuilder('phirewall.blocked')
                ->setAttribute('rule', $event->rule)
                ->startSpan();
            $span->end();
        }

        return $event;
    }
};
```

### Prometheus Metrics

```php
use Prometheus\CollectorRegistry;
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher = new class ($registry) implements EventDispatcherInterface {
    private $blockCounter;
    private $throttleCounter;
    private $latencyHistogram;

    public function __construct(CollectorRegistry $registry) {
        $this->blockCounter = $registry->getOrRegisterCounter(
            'phirewall', 'blocks_total', 'Total blocked requests', ['rule', 'type']
        );
        $this->throttleCounter = $registry->getOrRegisterCounter(
            'phirewall', 'throttles_total', 'Total throttled requests', ['rule']
        );
        $this->latencyHistogram = $registry->getOrRegisterHistogram(
            'phirewall', 'latency_microseconds', 'Decision latency',
            ['decision'], [10, 50, 100, 500, 1000, 5000]
        );
    }

    public function dispatch(object $event): object
    {
        match (true) {
            $event instanceof BlocklistMatched =>
                $this->blockCounter->inc(['rule' => $event->rule, 'type' => 'blocklist']),
            $event instanceof Fail2BanBanned =>
                $this->blockCounter->inc(['rule' => $event->rule, 'type' => 'fail2ban']),
            $event instanceof ThrottleExceeded =>
                $this->throttleCounter->inc(['rule' => $event->rule]),
            $event instanceof PerformanceMeasured =>
                $this->latencyHistogram->observe($event->durationMicros, ['decision' => $event->decisionPath]),
            default => null,
        };

        return $event;
    }
};
```

### Slack Alerting

```php
use GuzzleHttp\Client;
use Psr\EventDispatcher\EventDispatcherInterface;
use Flowd\Phirewall\Events\Fail2BanBanned;

$dispatcher = new class ($httpClient, $webhookUrl) implements EventDispatcherInterface {
    public function __construct(
        private Client $httpClient,
        private string $webhookUrl
    ) {}

    public function dispatch(object $event): object
    {
        // Only alert on bans
        if (!$event instanceof Fail2BanBanned) {
            return $event;
        }

        // Send async to avoid blocking
        $this->httpClient->postAsync($this->webhookUrl, [
            'json' => [
                'text' => sprintf(
                    ":shield: IP Banned: `%s` (Rule: %s, Failures: %d)",
                    $event->key,
                    $event->rule,
                    $event->count
                ),
            ],
        ]);

        return $event;
    }
};
```

---

## Diagnostics Counters

Lightweight in-memory counters for smoke tests and metrics endpoints.

### Getting Counters

```php
$counters = $config->getDiagnosticsCounters();

// Structure:
// [
//     'safelisted' => ['total' => 100, 'by_rule' => ['health' => 80, 'metrics' => 20]],
//     'blocklisted' => ['total' => 5, 'by_rule' => ['scanners' => 5]],
//     'throttle_exceeded' => ['total' => 2, 'by_rule' => ['ip-limit' => 2]],
//     'fail2ban_banned' => ['total' => 1, 'by_rule' => ['login' => 1]],
//     'track_hit' => ['total' => 50, 'by_rule' => ['api-calls' => 50]],
//     'passed' => ['total' => 10000, 'by_rule' => []],
// ]
```

### Counter Categories

| Category | Description |
|----------|-------------|
| `safelisted` | Requests that matched safelists |
| `blocklisted` | Requests blocked by blocklists |
| `throttle_exceeded` | Requests that exceeded rate limits |
| `fail2ban_blocked` | Requests blocked due to existing ban |
| `fail2ban_fail_hit` | Filter matches that count toward ban |
| `fail2ban_banned` | New bans issued |
| `track_hit` | Tracking rule matches |
| `passed` | Requests that passed all checks |

### Resetting Counters

```php
$config->resetDiagnosticsCounters();
```

### Exposing as Metrics Endpoint

```php
// In a /metrics endpoint
$counters = $config->getDiagnosticsCounters();

$output = '';
foreach ($counters as $category => $data) {
    $output .= "# HELP phirewall_{$category}_total Total {$category} events\n";
    $output .= "# TYPE phirewall_{$category}_total counter\n";
    $output .= "phirewall_{$category}_total {$data['total']}\n";

    foreach ($data['by_rule'] as $rule => $count) {
        $output .= "phirewall_{$category}_by_rule{{rule=\"{$rule}\"}} {$count}\n";
    }
}

return new Response(200, ['Content-Type' => 'text/plain'], $output);
```

---

## Performance Considerations

### Keep Handlers Fast

Event handlers run synchronously. Slow handlers impact request latency.

```php
// BAD - synchronous HTTP call
public function dispatch(object $event): object
{
    $this->httpClient->post($url, ['json' => $event]); // Blocks!
    return $event;
}

// GOOD - async or queue
public function dispatch(object $event): object
{
    $this->queue->push(['event' => $event::class, 'data' => $event]);
    return $event;
}
```

### Sample High-Volume Events

For high-traffic applications, sample TrackHit and PerformanceMeasured events:

```php
public function dispatch(object $event): object
{
    // Sample 1% of track hits
    if ($event instanceof TrackHit && random_int(1, 100) > 1) {
        return $event;
    }

    // Process normally
    $this->processEvent($event);
    return $event;
}
```

### Avoid Sensitive Data in Logs

Keys may contain IPs or user identifiers:

```php
// BAD - logs sensitive data
$this->logger->info('Event', ['key' => $event->key]);

// GOOD - hash or mask sensitive data
$maskedKey = substr($event->key, 0, 3) . '***';
$this->logger->info('Event', ['key_prefix' => $maskedKey]);
```

---

## Structured Logging Example

```php
use Flowd\Phirewall\Events\*;

$dispatcher = new class implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        $log = [
            'timestamp' => date('c'),
            'event' => (new \ReflectionClass($event))->getShortName(),
        ];

        // Add common fields
        if (property_exists($event, 'rule')) {
            $log['rule'] = $event->rule;
        }

        // Add request context
        if (property_exists($event, 'serverRequest')) {
            $req = $event->serverRequest;
            $log['request'] = [
                'method' => $req->getMethod(),
                'path' => $req->getUri()->getPath(),
                'ip' => $req->getServerParams()['REMOTE_ADDR'] ?? null,
                'user_agent' => $req->getHeaderLine('User-Agent'),
            ];
        }

        // Event-specific fields
        match (true) {
            $event instanceof ThrottleExceeded => $log += [
                'limit' => $event->limit,
                'count' => $event->count,
                'retry_after' => $event->retryAfter,
            ],
            $event instanceof Fail2BanBanned => $log += [
                'threshold' => $event->threshold,
                'ban_seconds' => $event->banSeconds,
            ],
            $event instanceof PerformanceMeasured => $log += [
                'decision' => $event->decisionPath,
                'latency_us' => $event->durationMicros,
            ],
            default => null,
        };

        // Output as JSON (to stdout, file, or log aggregator)
        fwrite(STDOUT, json_encode($log) . "\n");

        return $event;
    }
};
```

---

## Testing Events

```php
use PHPUnit\Framework\TestCase;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

class FirewallEventsTest extends TestCase
{
    public function testThrottleExceededEventDispatched(): void
    {
        $events = [];
        $dispatcher = new class ($events) implements EventDispatcherInterface {
            public function __construct(private array &$events) {}
            public function dispatch(object $event): object {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config(new InMemoryCache(), $dispatcher);
        $config->throttle('test', limit: 1, period: 60, key: fn($r) => 'key');

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/');

        // First request passes
        $firewall->decide($request);

        // Second request exceeds limit
        $firewall->decide($request);

        $throttleEvents = array_filter($events, fn($e) => $e instanceof ThrottleExceeded);
        $this->assertCount(1, $throttleEvents);
    }
}
```
