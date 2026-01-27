<?php

/**
 * Example 10: Observability with OpenTelemetry
 *
 * This example demonstrates how to integrate Phirewall events with
 * OpenTelemetry for distributed tracing and metrics.
 *
 * Features shown:
 * - PSR-14 event dispatcher with OpenTelemetry spans
 * - Firewall decision tracing
 * - Custom span attributes for blocked requests
 *
 * Optional dependency: open-telemetry/sdk
 *   composer require open-telemetry/sdk
 *
 * Run: php examples/10-observability-opentelemetry.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Observability with OpenTelemetry Example ===\n\n";

// =============================================================================
// OPENTELEMETRY SETUP (MOCK)
// =============================================================================

// This is a mock implementation for demonstration purposes.
// In production, you would use the actual OpenTelemetry SDK:
//
// use OpenTelemetry\API\Trace\TracerProviderInterface;
// use OpenTelemetry\SDK\Trace\TracerProvider;
// use OpenTelemetry\SDK\Trace\SpanExporter\ConsoleSpanExporter;
// use OpenTelemetry\SDK\Trace\SpanProcessor\SimpleSpanProcessor;

$mockTracer = new class {
    private array $spans = [];

    public function startSpan(string $name, array $attributes = []): object
    {
        $span = new class ($name, $attributes, $this->spans) {
            private float $startTime;
            private ?float $endTime = null;

            public function __construct(
                public readonly string $name,
                public array $attributes,
                private array &$spanLog
            ) {
                $this->startTime = microtime(true);
            }

            public function setAttribute(string $key, mixed $value): self
            {
                $this->attributes[$key] = $value;
                return $this;
            }

            public function setStatus(string $status): self
            {
                $this->attributes['status'] = $status;
                return $this;
            }

            public function end(): void
            {
                $this->endTime = microtime(true);
                $this->spanLog[] = [
                    'name' => $this->name,
                    'attributes' => $this->attributes,
                    'duration_ms' => round(($this->endTime - $this->startTime) * 1000, 2),
                ];
            }
        };

        return $span;
    }

    public function getSpans(): array
    {
        return $this->spans;
    }
};

echo "OpenTelemetry tracer configured (mock implementation)\n";
echo "In production, use the actual OpenTelemetry SDK\n\n";

// =============================================================================
// EVENT DISPATCHER WITH TRACING
// =============================================================================

$dispatcher = new class ($mockTracer) implements EventDispatcherInterface {
    public function __construct(private readonly object $tracer) {}

    public function dispatch(object $event): object
    {
        $eventType = (new \ReflectionClass($event))->getShortName();

        // Start a span for this event
        $span = $this->tracer->startSpan("phirewall.$eventType");

        // Add event-specific attributes
        if (property_exists($event, 'rule')) {
            $span->setAttribute('phirewall.rule', $event->rule);
        }
        if (property_exists($event, 'key')) {
            $span->setAttribute('phirewall.key', $event->key);
        }

        // Set status based on event type
        $status = match ($eventType) {
            'BlocklistMatched', 'Fail2BanBanned', 'ThrottleExceeded' => 'BLOCKED',
            'SafelistMatched', 'RequestPassed' => 'ALLOWED',
            default => 'OK',
        };
        $span->setStatus($status);
        $span->setAttribute('phirewall.decision', $status);

        // Simulate processing time (e.g., logging to external service)
        usleep(random_int(100, 500)); // 0.1-0.5ms

        $span->end();

        return $event;
    }
};

echo "Event dispatcher with tracing configured\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache, $dispatcher);

// Configure rules for demonstration
$config->throttle(
    name: 'api-limit',
    limit: 3,
    period: 60,
    key: KeyExtractors::ip()
);
echo "Throttle rule: 3 requests/min per IP\n";

$config->blocklist('malicious', function (ServerRequestInterface $req): bool {
    return str_contains($req->getUri()->getQuery(), 'attack');
});
echo "Blocklist rule: block requests with 'attack' in query\n";

$config->safelist('health', function (ServerRequestInterface $req): bool {
    return $req->getUri()->getPath() === '/health';
});
echo "Safelist rule: allow /health endpoint\n\n";

// =============================================================================
// MIDDLEWARE & HANDLER
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"status":"ok"}');
    }
};

// =============================================================================
// SIMULATION
// =============================================================================

echo "=== Request Simulation ===\n\n";

$requests = [
    ['GET', '/health', 'Health check (safelisted)'],
    ['GET', '/api/users', 'Normal API request #1'],
    ['GET', '/api/users', 'Normal API request #2'],
    ['GET', '/api/users', 'Normal API request #3'],
    ['GET', '/api/users', 'Normal API request #4 (should throttle)'],
    ['GET', '/api/data?attack=true', 'Malicious request (blocked)'],
];

foreach ($requests as [$method, $path, $desc]) {
    $request = new ServerRequest($method, $path, [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
    $response = $middleware->process($request, $handler);
    echo sprintf("  %-40s => %d\n", $desc, $response->getStatusCode());
}
echo "\n";

// =============================================================================
// TRACE SUMMARY
// =============================================================================

echo "=== Trace Summary (Spans) ===\n\n";

foreach ($mockTracer->getSpans() as $span) {
    echo sprintf("Span: %s\n", $span['name']);
    echo sprintf("  Duration: %.2f ms\n", $span['duration_ms']);
    foreach ($span['attributes'] as $key => $value) {
        echo sprintf("  %s: %s\n", $key, $value);
    }
    echo "\n";
}

// =============================================================================
// PRODUCTION INTEGRATION
// =============================================================================

echo "=== Production Integration ===\n\n";

echo "To use with real OpenTelemetry SDK:\n\n";

echo <<<'CODE'
use OpenTelemetry\API\Globals;
use OpenTelemetry\SDK\Trace\TracerProvider;
use OpenTelemetry\SDK\Trace\SpanExporter\OtlpHttpExporter;

// Initialize OpenTelemetry
$exporter = new OtlpHttpExporter('http://collector:4318/v1/traces');
$tracerProvider = new TracerProvider($exporter);
$tracer = $tracerProvider->getTracer('phirewall');

// In your event dispatcher:
$span = $tracer->spanBuilder("phirewall.$eventType")
    ->setAttribute('phirewall.rule', $event->rule)
    ->startSpan();

// ... process event ...

$span->end();
CODE;

echo "\n\n=== Example Complete ===\n";
