# Flowd-Firewall

Flowd-Firewall is a PSR-15 middleware providing application-level firewall features for PHP applications.

Features:
- Safelists (allow lists) — allowlisted requests bypass other checks
- Blocklists (deny lists) — deny with 403
- Throttling — limit requests per key within a time window, return 429 with Retry-After
- Fail2Ban — detect repeated failures and ban keys for a period
- Track hooks — increment custom counters for diagnostics/metrics without affecting outcome
- PSR-14 events — optional domain events for observability (safelist matched, blocklist matched, throttle exceeded, fail2ban banned, track hit)
- Custom response factories — override 403/429 responses while keeping standard headers

It uses a PSR-16 cache for counters/ban state. An in-memory cache is included for testing and simple usage. A Redis-backed store (via Predis client) is optionally available. The middleware can leverage enhanced capabilities via a lightweight CounterStoreInterface (increment/ttlRemaining) when the cache implements it; otherwise it falls back to generic PSR-16 behavior.

## Installation

Use Composer:

```
composer require flowd/phirewall
```

Optional backends:
- Redis: install Predis in your app: `composer require predis/predis`
- APCu: enable the PHP extension (ext-apcu). For CLI/testing, set `apc.enable_cli=1`

## Quick start

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\KeyExtractors;

$cache = new InMemoryCache(); // or any PSR-16 cache

// Or Redis (pure PHP via Predis):
// use Predis\Client as PredisClient;
// use Flowd\Phirewall\Store\RedisCache;
// $redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
// $cache = new RedisCache($redis);

$config = new Config($cache);

// Safelist health endpoint
$config->safelist('healthcheck', function ($req): bool {
    return $req->getUri()->getPath() === '/health';
});

// Blocklist a path
$config->blocklist('block-admin', function ($req): bool {
    return $req->getUri()->getPath() === '/admin';
});

// Throttle by IP
$config->throttle('ip', limit: 60, period: 60, key: KeyExtractors::ip());

// Fail2Ban for login failures
$config->fail2ban('login', threshold: 5, period: 300, ban: 3600,
    filter: function ($req): bool {
        return $req->getHeaderLine('X-Login-Failed') === '1';
    },
    key: function ($req): ?string {
        return $req->getServerParams()['REMOTE_ADDR'] ?? null;
    }
);

$middleware = new Middleware($config);
```

Add `$middleware` to your PSR-15 middleware pipeline.

### Response headers

- X-Flowd-Firewall: "blocklist" | "throttle" | "fail2ban"
- X-Flowd-Firewall-Matched: rule name that triggered
- X-Flowd-Firewall-Safelist: safelist name when bypass occurs
- Retry-After: seconds remaining in throttle window (for 429)

#### Optional: Standard rate-limit headers
You can opt-in to emitting standard X-RateLimit-* headers for throttle rules.

Enable once on your configuration:

```php
$config->enableRateLimitHeaders();
```

When enabled, for requests that match a throttle rule:
- On pass-through (not exceeding the limit), the 200 response will include:
  - X-RateLimit-Limit: the configured limit
  - X-RateLimit-Remaining: remaining requests in the current window
  - X-RateLimit-Reset: seconds until the window resets
- On throttled responses (429), the same headers are present with Remaining set to 0. The Retry-After header is still ensured by the middleware.

Notes:
- If multiple throttle rules apply, headers from the first applicable rule are used.
- Header values are based on fixed windows aligned to the period end.

### Events (optional)
If you pass a PSR-14 EventDispatcher to Config, the middleware emits domain-specific events you can observe:
- Events\SafelistMatched (fields: rule, request)
- Events\BlocklistMatched (fields: rule, request)
- Events\ThrottleExceeded (fields: rule, key, limit, period, count, retryAfter, request)
- Events\Fail2BanBanned (fields: rule, key, threshold, period, banSeconds, count, request)
- Events\TrackHit (fields: rule, key, period, count, request)

Basic wiring with a minimal dispatcher:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

// Very small dispatcher example (replace with your framework's dispatcher)
$dispatcher = new class () implements EventDispatcherInterface {
    public function dispatch(object $event): object
    {
        // Forward to your logging/metrics here
        error_log('Firewall event: ' . get_class($event));
        return $event;
    }
};

$config = new Config(new InMemoryCache(), $dispatcher);
$middleware = new Middleware($config);
```

Monolog integration example (no extra dependency required to use the library; this is optional):

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Psr\EventDispatcher\EventDispatcherInterface;

$logger = new Logger('firewall');
$logger->pushHandler(new StreamHandler('php://stdout'));

$dispatcher = new class ($logger) implements EventDispatcherInterface {
    public function __construct(private Logger $logger) {}
    public function dispatch(object $event): object
    {
        $context = get_object_vars($event);
        $this->logger->info('Firewall event', ['type' => get_class($event), 'context' => $context]);
        return $event;
    }
};
```

OpenTelemetry sketch (keep handlers lightweight; emit counters/spans as appropriate):

```php
// Pseudocode — integrate with your OTEL SDK setup
$dispatcher = new class ($tracer, $meter) implements Psr\\EventDispatcher\\EventDispatcherInterface {
    public function __construct(private $tracer, private $meter) {}
    public function dispatch(object $event): object
    {
        // Convert to metrics
        $this->meter->counter('firewall.events.total')->add(1, ['type' => get_class($event)]);
        // Optionally create spans for throttling decisions
        // $span = $this->tracer->spanBuilder('firewall.' . basename(str_replace('\\\\', '/', get_class($event))))->startSpan();
        // $span->end();
        return $event;
    }
};
```

Best practices:
- Keep event handlers fast; offload heavy work to async/queues.
- Avoid logging sensitive data (keys may include IPs or user identifiers).
- Consider sampling high-volume events like TrackHit.

See also example scripts:
- examples/observability_monolog.php — Monolog logger wiring
- examples/observability_opentelemetry.php — OpenTelemetry sketch

### Tracking hooks (optional)
Track custom conditions for observability without affecting request flow. Useful for counting login failures, suspicious paths, etc.

```php
// Track login failures by IP for 60s windows
$config->track('login_failed', period: 60,
    filter: function ($req): bool {
        return $req->getHeaderLine('X-Login-Failed') === '1';
    },
    key: function ($req): ?string {
        return $req->getServerParams()['REMOTE_ADDR'] ?? null;
    }
);
```

### Key extractors
Use KeyExtractors to quickly build keys for throttles, bans, and tracks without writing closures yourself.

```php
use Flowd\Phirewall\KeyExtractors;

// Throttle GET requests to /api by method+path combination
$config->throttle('api', limit: 100, period: 60, key: function ($req): ?string {
    $method = KeyExtractors::method()($req);
    $path = KeyExtractors::path()($req);
    return $method && $path ? $method . ':' . $path : null;
});
```

#### Client IP behind trusted proxies
When running behind reverse proxies/load balancers, use the TrustedProxyResolver to extract the real client IP securely:

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

$resolver = new TrustedProxyResolver([
    '127.0.0.1',      // local proxy
    '10.0.0.0/8',     // internal network
]);

// Throttle by client IP as seen through trusted proxies
$config->throttle('client-ip', limit: 60, period: 60, key: KeyExtractors::clientIp($resolver));
```

Security: the resolver only considers proxy headers if the immediate peer (REMOTE_ADDR) is trusted. It then walks X-Forwarded-For/Forwarded from right to left, skipping trusted proxies and selecting the first untrusted hop as the client IP. If uncertain, it falls back to REMOTE_ADDR.

### Custom responses (optional)
You can customize responses while standard headers are still ensured:

```php
$config->blocklistedResponse(function (string $rule, string $type, Psr\Http\Message\ServerRequestInterface $req): Psr\Http\Message\ResponseInterface {
    return new Nyholm\Psr7\Response(451, ['Content-Type' => 'application/json'], json_encode(['blocked' => $rule, 'type' => $type]));
});

$config->throttledResponse(function (string $rule, int $retryAfter, Psr\Http\Message\ServerRequestInterface $req): Psr\Http\Message\ResponseInterface {
    return (new Nyholm\Psr7\Response(429))->withHeader('X-Custom', 'yes');
});
```

### Storage backends
- InMemoryCache (bundled) implements PSR-16 and CounterStoreInterface for accurate fixed windows.
- ApcuCache (optional) implements PSR-16 and CounterStoreInterface using ext-apcu for fast in-process counters. Enable `apc.enable_cli=1` to use in CLI/testing environments.
- RedisCache (optional) implements PSR-16 and CounterStoreInterface using Predis. Redis is not required to use this package.
- Any PSR-16 cache will work; precision may be reduced without CounterStoreInterface.

### Key prefix (namespacing)
By default, Flowd-Firewall prefixes all keys it creates with `flowd-firewall`. You can change this to avoid collisions when multiple applications share a cache:

```php
$config->setKeyPrefix('myapp'); // Keys become: myapp:throttle:..., myapp:fail2ban:..., myapp:track:...
```

Notes:
- This affects keys created by the middleware regardless of the underlying cache.
- If you use RedisCache, it also applies its own internal namespace prefix (default `flowd-firewall:`). This is independent of the key prefix above and is used to avoid cross-tenant collisions in Redis. You can customize it when constructing RedisCache if desired.

### Key normalization and safety
To protect your cache from key poisoning and unbounded growth, Flowd-Firewall normalizes all dynamic key components (rule names and keys returned by your closures) before storing counters/bans:

- Allowed characters: A–Z, a–z, 0–9, dot (.), underscore (_), colon (:), and hyphen (-).
- Any other characters are replaced with an underscore and consecutive underscores are collapsed.
- Excessively long components are capped and a short SHA-1 suffix is appended to preserve uniqueness.

This normalization affects only internal cache keys. It does not alter headers, events, or your application-visible values.

### Rule evaluation order
The middleware evaluates rules in this order: safelist → blocklist → fail2ban → throttles.

## Examples

Real-world configuration snippets are available in the examples directory:

- examples/api_rate_limiting.php — Global per-client IP limit, stricter write-endpoint limits, and per-user limits with optional rate-limit headers
- examples/login_protection.php — Track login failures, Fail2Ban ban on repeated failures, and throttle login submissions
- examples/ip_banlists.php — Safelist health/metrics endpoints and block specific IPs or restrict admin to private networks
- examples/redis_setup.php — Use Redis (Predis) via RedisCache for distributed counters/bans

You can include any of these files from your bootstrap to obtain a configured middleware instance:

```
$firewall = require __DIR__ . '/examples/api_rate_limiting.php';
```

## Development

- Run unit tests: `XDEBUG_MODE=coverage vendor/bin/phpunit`
- Static analysis: `vendor/bin/phpstan`
- Code style: `vendor/bin/php-cs-fixer fix`

## License
This software package (“the Software”) is made available under a dual license. See the LICENSE file for details.
