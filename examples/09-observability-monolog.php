<?php

/**
 * Example 09: Observability with Monolog
 *
 * This example demonstrates how to integrate Phirewall events with Monolog
 * for logging firewall decisions, blocked requests, and rate limiting events.
 *
 * Features shown:
 * - PSR-14 event dispatcher integration
 * - Logging firewall events to Monolog
 * - Fallback to error_log if Monolog is not installed
 *
 * Optional dependency: monolog/monolog
 *   composer require monolog/monolog
 *
 * Run: php examples/09-observability-monolog.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Observability with Monolog Example ===\n\n";

// =============================================================================
// LOGGER SETUP
// =============================================================================

$logger = null;

if (class_exists(\Monolog\Logger::class)) {
    echo "Monolog detected - using Monolog for logging\n";
    $logger = new \Monolog\Logger('firewall');
    $logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stdout', \Monolog\Level::Info));
} else {
    echo "Monolog not installed - using error_log fallback\n";
    echo "Install with: composer require monolog/monolog\n";
}

echo "\n";

// =============================================================================
// EVENT DISPATCHER
// =============================================================================

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    private array $eventLog = [];

    public function __construct(private readonly ?object $logger) {}

    public function dispatch(object $event): object
    {
        $eventType = (new \ReflectionClass($event))->getShortName();
        $context = $this->summarize($event);

        // Store for later summary
        $this->eventLog[] = ['type' => $eventType, 'context' => $context];

        // Log the event
        if ($this->logger instanceof \Monolog\Logger) {
            $this->logger->info('Firewall event: ' . $eventType, $context);
        } else {
            error_log(sprintf('[Firewall] %s: %s', $eventType, json_encode($context, JSON_UNESCAPED_SLASHES)));
        }

        return $event;
    }

    /**
     * Extract a curated subset of the event for logging.
     *
     * Avoid serialising the embedded ServerRequest verbatim (e.g. via
     * `get_object_vars($event)` or `json_encode($event)`): the request
     * exposes every header and the parsed body, which are rarely useful
     * in aggregated logs and tend to be noisy. The discriminator `key`
     * is replaced with a short sha256 fingerprint so log lines can be
     * correlated by identity without storing the underlying value.
     *
     * @return array<string, mixed>
     */
    private function summarize(object $event): array
    {
        $context = [];

        if (property_exists($event, 'rule') && is_string($event->rule)) {
            $context['rule'] = $event->rule;
        }

        if (property_exists($event, 'key') && is_string($event->key) && $event->key !== '') {
            $context['key_fingerprint'] = substr(hash('sha256', $event->key), 0, 16);
        }

        if (property_exists($event, 'serverRequest') && $event->serverRequest instanceof ServerRequestInterface) {
            $request = $event->serverRequest;
            $context['method'] = $request->getMethod();
            $context['path'] = $request->getUri()->getPath();
            $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
            if (is_string($remoteAddr)) {
                $context['remote_addr'] = $remoteAddr;
            }
        }

        return $context;
    }

    public function getEventLog(): array
    {
        return $this->eventLog;
    }

    public function clear(): void
    {
        $this->eventLog = [];
    }
};

echo "Event dispatcher configured\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

$cache = new InMemoryCache();
$config = new Config($cache, $dispatcher);

// Simple throttle to demonstrate events
$config->throttles->add(
    name: 'ip-limit',
    limit: 3,
    period: 60
);
echo "Throttle rule configured: 3 requests/min per IP\n";

// Blocklist to demonstrate blocked events
$config->blocklists->add('scanner', fn(ServerRequestInterface $serverRequest): bool => str_contains(strtolower($serverRequest->getHeaderLine('User-Agent')), 'scanner'));
echo "Blocklist rule configured: block scanner User-Agents\n\n";

// =============================================================================
// MIDDLEWARE & HANDLER
// =============================================================================

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

// =============================================================================
// SIMULATION
// =============================================================================

echo "=== Request Simulation ===\n\n";

echo "Test 1: Normal requests (hitting rate limit)\n";
for ($i = 1; $i <= 5; ++$i) {
    $request = new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
    $response = $middleware->process($request, $handler);
    echo sprintf("  Request %d => %d\n", $i, $response->getStatusCode());
}

echo "\n";

echo "Test 2: Blocked scanner request\n";
$request = new ServerRequest('GET', '/', ['User-Agent' => 'Evil-Scanner/1.0'], null, '1.1', ['REMOTE_ADDR' => '10.0.0.50']);
$response = $middleware->process($request, $handler);
echo sprintf("  Scanner request => %d\n", $response->getStatusCode());
echo "\n";

// =============================================================================
// EVENT SUMMARY
// =============================================================================

echo "=== Event Summary ===\n\n";

$eventCounts = [];
foreach ($dispatcher->getEventLog() as $entry) {
    $type = $entry['type'];
    $eventCounts[$type] = ($eventCounts[$type] ?? 0) + 1;
}

echo "Events fired:\n";
foreach ($eventCounts as $type => $count) {
    echo sprintf("  - %s: %d\n", $type, $count);
}

echo "\n";

// =============================================================================
// PRODUCTION TIPS
// =============================================================================

echo "=== Production Tips ===\n\n";

echo "1. Event types you can listen for:\n";
echo "   - RequestPassed: Request allowed through\n";
echo "   - ThrottleExceeded: Rate limit hit\n";
echo "   - ThrottleChecked: Rate limit checked (passed)\n";
echo "   - BlocklistMatched: Request matched blocklist\n";
echo "   - Fail2BanBanned: IP banned by Fail2Ban\n";
echo "   - SafelistMatched: Request matched safelist\n";
echo "\n";

echo "2. Logging recommendations:\n";
echo "   - Log BlocklistMatched and Fail2BanBanned at WARNING level\n";
echo "   - Log ThrottleExceeded at INFO level\n";
echo "   - Log RequestPassed at DEBUG level (high volume)\n";
echo "   - Extract a curated subset rather than serialising the whole event:\n";
echo "     get_object_vars(\$event) / json_encode(\$event) include the full\n";
echo "     ServerRequest (every header + parsed body) and produce noisy logs.\n";
echo "     See the \$dispatcher->summarize() helper above.\n";
echo "\n";

echo "3. Alerting suggestions:\n";
echo "   - Alert on high volume of BlocklistMatched from single IP\n";
echo "   - Alert on Fail2BanBanned events\n";
echo "   - Monitor ThrottleExceeded trends\n";

echo "\n=== Example Complete ===\n";
