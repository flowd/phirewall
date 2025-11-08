<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Example: IP allow/ban lists
 *
 * - Safelist internal endpoints (health/metrics)
 * - Block known bad IPs
 * - Optionally block access to sensitive paths from non-private networks
 */

$cache = new InMemoryCache();
$resolver = new TrustedProxyResolver([
    '127.0.0.1',
    '10.0.0.0/8',
]);

$config = new Config($cache);

// Safelist common internal endpoints so they bypass all other checks
$config->safelist('health', fn (ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/health');
$config->safelist('metrics', fn (ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/metrics');

// Block known bad IPs (could be loaded from a database or config file)
$blockedIps = [
    '203.0.113.10',
    '198.51.100.22',
];
$config->blocklist('ip_banlist', function (ServerRequestInterface $serverRequest) use ($resolver, $blockedIps): bool {
    $ip = $resolver->resolve($serverRequest);
    return $ip !== null && in_array($ip, $blockedIps, true);
});

// Optional: block access to /admin from outside private networks
$config->blocklist('admin_external', function (ServerRequestInterface $serverRequest) use ($resolver): bool {
    $path = $serverRequest->getUri()->getPath();
    if ($path !== '/admin') {
        return false;
    }

    $ip = $resolver->resolve($serverRequest);
    if ($ip === null) {
        return true; // unknown => block
    }

    // Allow RFC1918 private ranges only
    foreach (['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] as $cidr) {
        // Simple check via PHP's ip2long masking
        if (str_contains($cidr, '/')) {
            [$subnet, $mask] = explode('/', $cidr, 2);
            $mask = (int)$mask;
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            if ($ipLong !== false && $subnetLong !== false) {
                $maskLong = $mask === 0 ? 0 : (~0 << (32 - $mask)) & 0xFFFFFFFF;
                if (($ipLong & $maskLong) === ($subnetLong & $maskLong)) {
                    return false; // allow private
                }
            }
        }
    }

    return true; // non-private => block
});

$middleware = new Middleware($config, new Psr17Factory());

// If executed directly, run a small demonstration with simulated requests.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
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
        foreach (['X-Phirewall','X-Phirewall-Matched'] as $h) {
            $val = $response->getHeaderLine($h);
            if ($val !== '') {
                echo $h . ': ' . $val . "\n";
            }
        }

        echo "\n";
    };

    // Safelisted endpoints
    $run('GET', '/health', [], ['REMOTE_ADDR' => '203.0.113.5']);
    $run('GET', '/metrics', [], ['REMOTE_ADDR' => '203.0.113.5']);
    // Blocked admin from external IP
    $run('GET', '/admin', [], ['REMOTE_ADDR' => '198.51.100.77']);

    exit(0);
}

return $middleware;
