<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    throw new RuntimeException('Run this example via CLI: php examples/redis_setup.php');
}

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Example: Using Redis for counters/bans (optional)
 *
 * Requires predis/predis in your application:
 *   composer require predis/predis
 *
 * Set REDIS_URL env var if desired (e.g., redis://localhost:6379/0)
 */
// If Predis is not installed or Redis is unavailable, this example will print a helpful message when executed directly.
// Fallback stub to allow including the file without fatal errors
if (!class_exists(\Predis\Client::class)) {
    fwrite(STDERR, "Predis is not installed. Run: composer require predis/predis\n");
    exit(1);
}

$redisClient = new \Predis\Client(getenv('REDIS_URL') ?: 'redis://localhost:6379');

$cache = new RedisCache($redisClient, 'phirewall:demo:');

$config = new Config($cache);

// Simple throttle by direct IP (no proxy trust). For proxies, combine with TrustedProxyResolver.
$config->throttle('ip', 1, 10, KeyExtractors::ip());

$middleware = new Middleware($config, new Psr17Factory());

// If executed directly, run a small demonstration hitting the throttle quickly.
try {
    $pong = (string)$redisClient->ping();
    if (stripos($pong, 'PONG') === false) {
        fwrite(STDERR, "Redis did not respond with PONG\n");
        exit(1);
    }
} catch (\Throwable $throwable) {
    fwrite(STDERR, "Redis not reachable: " . $throwable->getMessage() . "\n");
    exit(1);
}

$handler = new class () implements RequestHandlerInterface {
    public function handle(\Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

$run = static function (string $method, string $path, array $headers = [], array $server = []) use ($middleware, $handler): void {
    $request = new ServerRequest($method, $path, $headers, null, '1.1', $server);
    $response = $middleware->process($request, $handler);
    $addr = $server['REMOTE_ADDR'] ?? 'n/a';
    echo sprintf("%s %s from %s => %d\n", $method, $path, $addr, $response->getStatusCode());
    foreach (['X-Phirewall','X-Phirewall-Matched','Retry-After'] as $h) {
        $val = $response->getHeaderLine($h);
        if ($val !== '') {
            echo $h . ': ' . $val . "\n";
        }
    }

    echo "\n";
};

$run('GET', '/', [], ['REMOTE_ADDR' => '203.0.113.9']);
$run('GET', '/', [], ['REMOTE_ADDR' => '203.0.113.9']);

exit(0);
