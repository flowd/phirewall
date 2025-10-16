<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Example: Observability with OpenTelemetry (sketch)
 *
 * This example demonstrates how you might bridge firewall events to an OpenTelemetry
 * tracer and meter. It avoids adding dependencies; replace the $tracer/$meter with
 * your SDK setup. Keep handlers lightweight to avoid request latency.
 */

$cache = new InMemoryCache();

// Pseudocode tracer/meter; replace with your actual OTEL SDK instances
$tracer = null; // e.g., (new TracerProvider(...))->getTracer('app');
$meter  = null; // e.g., (new MeterProvider(...))->getMeter('app');

$dispatcher = new class ($tracer, $meter) implements EventDispatcherInterface {
    public function __construct(private readonly ?object $tracer, private readonly ?object $meter) {}
    public function dispatch(object $event): object
    {
        $type = get_class($event);
        // Record a metric counter if available
        if ($this->meter && method_exists($this->meter, 'counter')) {
            // Counter API is SDK-specific; adjust accordingly
            try {
                $this->meter->counter('firewall.events.total')->add(1, ['type' => $type]);
            } catch (\Throwable) {
                // no-op
            }
        }
        // Optionally create very short spans for decision points
        if ($this->tracer && method_exists($this->tracer, 'spanBuilder')) {
            try {
                $short = ($pos = strrpos($type, '\\')) !== false ? substr($type, $pos + 1) : $type;
                $spanName = 'firewall.' . strtolower($short);
                $span = $this->tracer->spanBuilder($spanName)->startSpan();
                $span->end();
            } catch (\Throwable) {
                // no-op
            }
        }
        return $event;
    }
};

$config = new Config($cache, $dispatcher);
$config->throttle('ip', limit: 3, period: 30, key: KeyExtractors::ip());

$middleware = new Middleware($config);

// If executed directly, run a tiny demonstration
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $handler = new class () implements RequestHandlerInterface {
        public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
        }
    };

    $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.99']);
    for ($i = 1; $i <= 5; $i++) {
        $response = $middleware->process($request, $handler);
        echo sprintf("Attempt %d => %d\n", $i, $response->getStatusCode());
    }

    exit(0);
}

return $middleware;
