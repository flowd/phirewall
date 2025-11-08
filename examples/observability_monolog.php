<?php

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
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Example: Observability with Monolog
 *
 * This example wires a simple PSR-14 dispatcher that forwards Phirewall events
 * to a Monolog logger. Monolog is optional; this library does not require it.
 */

$cache = new InMemoryCache();

// If Monolog is installed, set up a logger. Otherwise, fall back to error_log.
$logger = null;
if (class_exists(\Monolog\Logger::class)) {
    $logger = new \Monolog\Logger('firewall');
    // Write to stdout; adjust as needed for your environment
    $logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stdout'));
}

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    public function __construct(private readonly ?object $logger) {}

    public function dispatch(object $event): object
    {
        $type = $event::class;
        $context = method_exists($event, '__debugInfo') ? $event->__debugInfo() : get_object_vars($event);
        if ($this->logger instanceof \Monolog\Logger) {
            $this->logger->info('Firewall event', ['type' => $type, 'context' => $context]);
        } else {
            // Fallback if Monolog not available (intentional logging for the example)
            error_log('[Firewall] ' . $type . ' ' . json_encode($context, JSON_UNESCAPED_SLASHES));
        }

        return $event;
    }
};

$config = new Config($cache, $dispatcher);
$config->throttle('ip', limit: 5, period: 60, key: KeyExtractors::ip());

$middleware = new Middleware($config, new Psr17Factory());

// If executed directly, run a tiny demonstration
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $handler = new class () implements RequestHandlerInterface {
        public function handle(ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
        {
            return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
        }
    };

    $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
    for ($i = 1; $i <= 7; ++$i) {
        $response = $middleware->process($request, $handler);
        echo sprintf("Attempt %d => %d\n", $i, $response->getStatusCode());
    }

    exit(0);
}

return $middleware;
