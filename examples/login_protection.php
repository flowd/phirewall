<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Example: Login protection
 *
 * - Track login failures for observability
 * - Fail2Ban when too many failures occur within a window
 * - Throttle login submissions per client to slow brute-force attempts
 * - Optional custom responses
 */

$cache = new InMemoryCache();
$resolver = new TrustedProxyResolver([
    '127.0.0.1',
    '10.0.0.0/8',
]);

$config = new Config($cache);
$config->setKeyPrefix('myapp');

// Track login failures by client IP for 60-second windows
$config->track('login_failed', 60,
    filter: fn(ServerRequestInterface $request): bool => $request->getUri()->getPath() === '/login' && $request->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::clientIp($resolver)
);

// Fail2Ban: 5 failed attempts in 5 minutes => ban IP for 1 hour
$config->fail2ban('login_abuse', threshold: 5, period: 300, ban: 3600,
    filter: fn(ServerRequestInterface $request): bool => $request->getUri()->getPath() === '/login' && $request->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::clientIp($resolver)
);

// Throttle login submissions per client: 10 attempts per minute
$config->throttle('login_submit', limit: 10, period: 60, key: KeyExtractors::clientIp($resolver));

// Optional: customize blocklisted/fail2ban response
$config->blocklistedResponse(fn(string $rule, string $type, ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface => new Response(403, ['Content-Type' => 'application/json', 'X-Flow' => 'blocked'], json_encode([
    'blocked' => $rule,
    'type' => $type,
], JSON_THROW_ON_ERROR)));

$middleware = new Middleware($config);

// If executed directly, run a small demonstration with simulated requests.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $handler = new class () implements RequestHandlerInterface {
        public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
        }
    };

    $run = static function (string $method, string $path, array $headers = [], array $server = []) use ($middleware, $handler): void {
        $request = new ServerRequest($method, $path, $headers, null, '1.1', $server);
        $response = $middleware->process($request, $handler);
        $addr = $server['REMOTE_ADDR'] ?? 'n/a';
        echo sprintf("%s %s from %s => %d\n", $method, $path, $addr, $response->getStatusCode());
        foreach (['X-Flowd-Firewall','X-Flowd-Firewall-Matched','Retry-After'] as $h) {
            $val = $response->getHeaderLine($h);
            if ($val !== '') {
                echo $h . ': ' . $val . "\n";
            }
        }
        echo "\n";
    };

    // Simulate 5 failed login attempts to trigger Fail2Ban, then a blocked request
    for ($i = 1; $i <= 5; $i++) {
        $run('POST', '/login', ['X-Login-Failed' => '1'], ['REMOTE_ADDR' => '198.51.100.2']);
    }
    // Next request (without failure header) should be banned
    $run('GET', '/', [], ['REMOTE_ADDR' => '198.51.100.2']);

    exit(0);
}

return $middleware;
