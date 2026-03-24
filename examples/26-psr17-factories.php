<?php

/**
 * Example 26: PSR-17 Response Factories
 *
 * This example demonstrates how to use standard PSR-17 response/stream factories
 * so that Phirewall builds 403 and 429 responses using your framework's native
 * HTTP message implementation.
 *
 * Features shown:
 * - Configuring PSR-17 factories for blocklisted and throttled responses
 * - Custom body text for blocked/throttled responses
 * - Integration through the full middleware stack
 *
 * Run: php examples/26-psr17-factories.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Response\Psr17BlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\Psr17ThrottledResponseFactory;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== PSR-17 Response Factories Example ===\n\n";

// =============================================================================
// SETUP
// =============================================================================

$cache = new InMemoryCache();
$psr17Factory = new Psr17Factory(); // implements both ResponseFactoryInterface and StreamFactoryInterface

// Simple handler that returns 200 OK
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "Hello, World!\n");
    }
};

// Helper to show response details
$showResponse = function (string $label, ResponseInterface $response): void {
    echo sprintf("  %-45s => %d\n", $label, $response->getStatusCode());
    foreach (['Content-Type', 'Retry-After', 'X-Phirewall', 'X-Phirewall-Matched'] as $header) {
        $value = $response->getHeaderLine($header);
        if ($value !== '') {
            echo sprintf("    %s: %s\n", $header, $value);
        }
    }

    $body = (string) $response->getBody();
    if ($body !== '') {
        echo sprintf("    Body: %s\n", $body);
    }
};

// =============================================================================
// APPROACH 1: Quick setup with usePsr17Responses()
// =============================================================================

echo "--- Approach 1: usePsr17Responses() convenience method ---\n\n";

$config = new Config($cache);
$config->usePsr17Responses($psr17Factory, $psr17Factory);
$config->blocklists->add('admin', fn(ServerRequestInterface $serverRequest): bool => str_starts_with($serverRequest->getUri()->getPath(), '/admin'));
$config->throttles->add('ip', 2, 60, KeyExtractors::ip());

$middleware = new Middleware($config, $psr17Factory);

// Blocklisted request
$showResponse(
    'GET /admin (blocklisted)',
    $middleware->process(new ServerRequest('GET', '/admin'), $handler),
);
echo "\n";

// Throttled requests
$ip = '10.0.0.1';
for ($i = 1; $i <= 3; ++$i) {
    $showResponse(
        sprintf('GET /api (request %d from %s)', $i, $ip),
        $middleware->process(
            new ServerRequest('GET', '/api', [], null, '1.1', ['REMOTE_ADDR' => $ip]),
            $handler,
        ),
    );
}

echo "\n";

// =============================================================================
// APPROACH 2: Individual factories with custom body text
// =============================================================================

echo "--- Approach 2: Individual factories with custom body text ---\n\n";

$cache2 = new InMemoryCache();
$config2 = new Config($cache2);
$config2->blocklistedResponseFactory = new Psr17BlocklistedResponseFactory(
    $psr17Factory,
    $psr17Factory,
    'Access Denied — your request has been blocked.',
);
$config2->throttledResponseFactory = new Psr17ThrottledResponseFactory(
    $psr17Factory,
    $psr17Factory,
    'Rate limit exceeded. Please slow down.',
);
$config2->blocklists->add('blocked', fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/secret');
$config2->throttles->add('ip', 1, 30, KeyExtractors::ip());

$middleware2 = new Middleware($config2, $psr17Factory);

$showResponse(
    'GET /secret (custom blocked text)',
    $middleware2->process(new ServerRequest('GET', '/secret'), $handler),
);
echo "\n";

// Exhaust quota then trigger throttle
$middleware2->process(
    new ServerRequest('GET', '/api', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']),
    $handler,
);
$showResponse(
    'GET /api (custom throttled text)',
    $middleware2->process(
        new ServerRequest('GET', '/api', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']),
        $handler,
    ),
);
echo "\n";

echo "=== Example Complete ===\n";
