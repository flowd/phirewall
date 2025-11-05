<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

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
if (!class_exists(\Predis\Client::class)) {
    // Fallback stub to allow including the file without fatal errors
    if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
        fwrite(STDERR, "Predis is not installed. Run: composer require predis/predis\n");
        exit(0);
    }
}

// @phpstan-ignore-next-line - Predis may not be installed in all environments
$redisClient = class_exists(\Predis\Client::class) ? new \Predis\Client(getenv('REDIS_URL') ?: 'redis://localhost:6379') : null;

if ($redisClient === null) {
    // Provide a no-op return when included
    $config = new Config(new class implements \Psr\SimpleCache\CacheInterface {
        public function get(string $key, mixed $default = null): mixed { return $default; }
        public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool { return true; }
        public function delete(string $key): bool { return true; }
        public function clear(): bool { return true; }
        public function getMultiple(iterable $keys, mixed $default = null): iterable { return []; }
        public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool { return true; }
        public function deleteMultiple(iterable $keys): bool { return true; }
        public function has(string $key): bool { return false; }
    });
    $middleware = new Middleware($config, new Psr17Factory());

    if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
        fwrite(STDERR, "Predis is not installed. Example cannot demonstrate Redis without it.\n");
        exit(0);
    }

    return $middleware;
}

// Use a namespaced prefix to avoid collisions (default is 'phirewall:')
$cache = new RedisCache($redisClient, 'phirewall:demo:');

$config = new Config($cache);

// Simple throttle by direct IP (no proxy trust). For proxies, combine with TrustedProxyResolver.
$config->throttle('ip', 1, 10, KeyExtractors::ip());

$middleware = new Middleware($config, new Psr17Factory());

// If executed directly, run a small demonstration hitting the throttle quickly.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    // Ping Redis to ensure connectivity
    try {
        $pong = (string)$redisClient->ping();
        if (stripos($pong, 'PONG') === false) {
            fwrite(STDERR, "Redis did not respond with PONG\n");
            exit(0);
        }
    } catch (\Throwable $e) {
        fwrite(STDERR, "Redis not reachable: " . $e->getMessage() . "\n");
        exit(0);
    }

    $handler = new class () implements RequestHandlerInterface {
        public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
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
}

return $middleware;
