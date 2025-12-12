<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    throw new RuntimeException('Run this example via CLI: php examples/api_rate_limiting.php');
}

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Example: API rate limiting strategy
 *
 * - Global per-client-IP limit: 100 requests per minute
 * - Stricter limits for write endpoints under /api
 * - Per-authenticated-user limits based on X-User-Id header (if present)
 * - Emits X-RateLimit-* headers when enabled
 */

$cache = new InMemoryCache(); // or use any PSR-16 cache

// If you are behind proxies/load balancers, define trusted proxies to resolve client IPs safely.
$resolver = new TrustedProxyResolver([
    '127.0.0.1',   // local proxy
    '10.0.0.0/8',  // internal network
]);

$config = new Config($cache);
$config->enableRateLimitHeaders();

// Global per-client-IP limit: 100 requests per 60 seconds
$config->throttle('api_global_ip', 10, 60, KeyExtractors::clientIp($resolver));

// Stricter limits for write endpoints (POST/PUT/PATCH/DELETE) under /api
$config->throttle('api_write', 5, 60, function (ServerRequestInterface $serverRequest): ?string {
    $method = strtoupper($serverRequest->getMethod());
    $path = $serverRequest->getUri()->getPath();
    if (str_starts_with($path, '/api/') && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return $method . ':' . $path; // method+path key
    }

    return null; // skip for other routes
});

// Per-authenticated user limit (assuming your app sets X-User-Id after auth)
$config->throttle('api_user', 300, 900, KeyExtractors::header('X-User-Id'));

$middleware = new Middleware($config, new Psr17Factory());

$handler = new class () implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

$run = static function (string $method, string $path, array $headers = [], array $server = []) use ($middleware, $handler): void {
    $request = new ServerRequest($method, $path, $headers, null, '1.1', $server);
    $response = $middleware->process($request, $handler);
    $addr = $server['REMOTE_ADDR'] ?? 'n/a';
    echo sprintf("%s %s from %s => %d\n", $method, $path, $addr, $response->getStatusCode());
    foreach (['X-Phirewall','X-Phirewall-Matched','Retry-After','X-RateLimit-Limit','X-RateLimit-Remaining','X-RateLimit-Reset'] as $h) {
        $val = $response->getHeaderLine($h);
        if ($val !== '') {
            echo $h . ': ' . $val . "\n";
        }
    }

    echo "\n";
};

$run('GET', '/api/users', [], ['REMOTE_ADDR' => '198.51.100.1']);
for ($i = 1; $i <= 10; ++$i) {
    $run('POST', '/api/users', ['X-User-Id' => '42'], ['REMOTE_ADDR' => '198.51.100.1']);
}

exit(0);
