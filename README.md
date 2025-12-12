# Phirewall

Phirewall is a PHP based application firewall that provides a PSR-15 middleware.

<img src="docs/assets/logo.svg" width="300" alt="Phirewall Logo">

Features:
- Safelists (allow lists) — allowlisted requests bypass other checks
- Blocklists (deny lists) — deny with 403
- Throttling — limit requests per key within a time window, return 429 with Retry-After
- Fail2Ban — detect repeated failures and ban keys for a period
- Track hooks — increment custom counters for diagnostics/metrics without affecting outcome
- Pattern backends/frontends — pluggable pattern sources (file/redis/db/etc.) feeding blocklist frontends with IP/CIDR/path/header/regex kinds
- PSR-14 events — optional domain events for observability (safelist matched, blocklist matched, throttle exceeded, fail2ban banned, track hit, performance measured)
- Diagnostics counters — lightweight per-category/rule counters for smoke tests or exposing metrics endpoints
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
use Nyholm\Psr7\Factory\Psr17Factory;

$cache = new InMemoryCache(); // or any PSR-16 cache
$responseFactory = new Psr17Factory();

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

$middleware = new Middleware($config, $responseFactory);
```

Add the middleware to your PSR-15 pipeline and ensure a PSR-17 ResponseFactory is available. The middleware will attempt to auto-detect one via `Flowd\Phirewall\Http\ResponseFactoryResolver`; if no supported implementation (Nyholm, Guzzle, Laminas, Slim, etc.) is installed you must pass your own factory instance, otherwise construction fails.

### Response headers

- X-Phirewall: "blocklist" | "throttle" | "fail2ban"
- X-Phirewall-Matched: rule name that triggered
- X-Phirewall-Safelist: safelist name when bypass occurs
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
- Events\PerformanceMeasured (fields: decisionPath, durationMicros, ruleName) — dispatched for every decision so you can instrument latency

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

Security: the resolver only considers proxy headers if the immediate peer (REMOTE_ADDR) is trusted. It then walks X-Forwarded-For/Forwarded from right to left, skipping trusted proxies and selecting the first untrusted hop as the client IP. If uncertain, it falls back to REMOTE_ADDR. You can further harden resolution by:
- Passing `allowedHeaders` (e.g., only `['Forwarded']`) when constructing `TrustedProxyResolver` to restrict which headers are honoured.
- Tuning `maxChainEntries` to drop overly long X-Forwarded-For chains and mitigate header-injection attempts.
- Using IPv4/IPv6 CIDR ranges (e.g., `2001:db8::/32`) in the trusted list so dual-stack deployments stay accurate.

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
- RedisCache (optional) implements PSR-16 and CounterStoreInterface using Predis. It uses Lua (`INCR` + `EXPIREAT`) to align expiries with the end of the current window and falls back to returning `0` if Redis is unavailable so your app can decide how to fail open. Redis is not required to use this package.
- Any PSR-16 cache will work; precision may be reduced without CounterStoreInterface.

### Key prefix (namespacing)
By default, Phirewall prefixes all keys it creates with `phirewall`. You can change this to avoid collisions when multiple applications share a cache:

```php
$config->setKeyPrefix('myapp'); // Keys become: myapp:throttle:..., myapp:fail2ban:..., myapp:track:...
```

Notes:
- This affects keys created by the middleware regardless of the underlying cache.
- If you use RedisCache, it also applies its own internal namespace prefix (default `phirewall:`). This is independent of the key prefix above and is used to avoid cross-tenant collisions in Redis. You can customize it when constructing RedisCache if desired.

### Key normalization and safety
To protect your cache from key poisoning and unbounded growth, Phirewall normalizes all dynamic key components (rule names and keys returned by your closures) before storing counters/bans:

- Allowed characters: A–Z, a–z, 0–9, dot (.), underscore (_), colon (:), and hyphen (-).
- Any other characters are replaced with an underscore and consecutive underscores are collapsed.
- Excessively long components are capped and a short SHA-1 suffix is appended to preserve uniqueness.

This normalization affects only internal cache keys. It does not alter headers, events, or your application-visible values.

### Rule evaluation order
The middleware evaluates rules in this order: safelist → blocklist → fail2ban → throttles.

### Configuration flags & options
- enableRateLimitHeaders(bool $enabled = true): opt-in standard X-RateLimit-* headers on pass-through and throttled responses.
- setKeyPrefix(string $prefix): set a global prefix for all generated counter/ban/track keys (default: phirewall).
- blocklistedResponse(Closure $factory): customize 403/fail2ban responses while middleware still ensures X-Phirewall headers.
- throttledResponse(Closure $factory): customize 429 responses; middleware ensures Retry-After if missing.
- Event dispatcher (PSR-14): pass a dispatcher to Config’s constructor to receive observability events.
- Cache backend (PSR-16): pass any PSR-16 implementation to Config; CounterStoreInterface improves window accuracy.

### Redis setup
- Install Predis: composer require predis/predis
- Provide a client URL via REDIS_URL or construct client manually.
- Use RedisCache to wrap the client and pass it to Config. See examples/redis_setup.php.
- Notes: Redis is optional; in-memory/APCu backends work without Redis.

### Security guidelines
- Do not trust client-provided IP headers unless behind trusted proxies. Use TrustedProxyResolver and KeyExtractors::clientIp().
- Be mindful of logging privacy: keys may include IPs or identifiers; avoid storing sensitive data in logs/metrics.
- Key normalization prevents cache poisoning and key explosion by restricting characters and capping length.
- Prefer per-endpoint/method throttles for sensitive actions (login, password reset) and stricter limits on writes.
- Validate and sanitize user inputs in your application in addition to rate limiting (OWASP ASVS guidance applies).

## Infrastructure adapters (optional)

### Apache .htaccess adapter
This library includes an optional infrastructure adapter that can mirror application-level blocks to Apache by maintaining a managed section in an `.htaccess` file using `Require not ip` directives (Apache 2.4+).

- Non-blocking: wire it through `InfrastructureBanListener` with a `NonBlockingRunnerInterface` implementation (e.g., `SyncNonBlockingRunner` or a custom async runner).
- Safe by design: validates IPs, preserves unrelated `.htaccess` content, and uses atomic writes.
- Extensible: third parties can implement `InfrastructureBlockerInterface` for other backends (nginx, WAF, firewall CLI).

Minimal usage:

```php
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;

$adapter = new ApacheHtaccessAdapter('/var/www/app/.htaccess');
$adapter->blockMany(['203.0.113.10', '2001:db8::1']);
$adapter->unblockIp('203.0.113.10');
```

See a runnable example at `examples/apache_htaccess_adapter.php`.

Security notes:
- Only enable server-level blocking when you fully control deployment and permissions.
- Ensure the process has write permissions to the `.htaccess` target.
- This is opt-in and not required for the middleware to function.

## Real-world use cases

Below are copy-pasteable recipes you can adapt to your application. They are framework-agnostic and use PSR-7/15 types.

### 1) API-wide rate limit by client IP with standard headers

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
$config = new Config($cache);

// Emit standard X-RateLimit-* headers
$config->enableRateLimitHeaders();

// 100 requests per minute per IP
$config->throttle('api-ip-minute', limit: 100, period: 60, key: KeyExtractors::ip());

$middleware = new Middleware($config);
```

Notes:
- If you run behind a proxy, use `KeyExtractors::clientIp(TrustedProxyResolver)` instead of `ip()`.

### 2) Login protection: Fail2Ban + throttle

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$config = new Config(new RedisCache($redis));

// Fail2Ban: if header X-Login-Failed=1 occurs >=5 times in 5 min, ban IP for 1 hour
$config->fail2ban('login', threshold: 5, period: 300, ban: 3600,
    filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

// Also throttle login submissions to 10/min per IP
$config->throttle('login-ip-minute', limit: 10, period: 60, key: KeyExtractors::ip());

$middleware = new Middleware($config);
```

### 3) Per-user limits (API key/JWT subject) + separate anonymous IP throttle

```php
use Flowd\Phirewall\KeyExtractors;

$userKey = function ($req): ?string {
    // Example: read user id from header injected by your auth layer
    $uid = $req->getHeaderLine('X-User-Id');
    return $uid !== '' ? $uid : null;
};

// Authenticated users: 600/min per user id
$config->throttle('user-minute', limit: 600, period: 60, key: $userKey);

// Anonymous traffic: 60/min per IP
$config->throttle('anon-ip-minute', limit: 60, period: 60, key: KeyExtractors::ip());
```

### 4) Route-specific stricter throttle (e.g., POST /search) and by method

```php
$config->throttle('search-post', limit: 20, period: 60, key: function ($req): ?string {
    if ($req->getMethod() !== 'POST' || $req->getUri()->getPath() !== '/search') {
        return null; // skip rule for non-matching requests
    }
    // key by IP to bound abuse per client
    return $req->getServerParams()['REMOTE_ADDR'] ?? null;
});

// Method-aware key, e.g., GET bucket separate from POST
$config->throttle('method+ip', limit: 200, period: 60, key: function ($req): ?string {
    $method = $req->getMethod();
    $ip = $req->getServerParams()['REMOTE_ADDR'] ?? null;
    return $ip ? $method . ':' . $ip : null;
});
```

### 5) Burst + sustained combined limits on the same key

```php
$byIp = fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null;

// Allow short burst: 30 in 10s
$config->throttle('burst', limit: 30, period: 10, key: $byIp);
// And a sustained limit: 300 in 5 min
$config->throttle('sustained', limit: 300, period: 300, key: $byIp);
```

### 6) Safelist health checks and internal ranges

```php
$config->safelist('health', fn($req): bool => $req->getUri()->getPath() === '/health');
$config->safelist('internal-cidr', function ($req): bool {
    $ip = $req->getServerParams()['REMOTE_ADDR'] ?? '';
    // Simple check example — replace with a real CIDR matcher for production
    return str_starts_with($ip, '10.') || str_starts_with($ip, '192.168.');
});
```

### 7) Webhook receiver hardening: blocklist invalid signatures + Fail2Ban

```php
$signatureInvalid = function ($req): bool {
    // Replace with your real validation
    return $req->getHeaderLine('X-Signature-Valid') === '0';
};

// Immediately 403 requests that look like targeted probing
$config->blocklist('webhook-probe', fn($req): bool => $signatureInvalid($req) && $req->getMethod() !== 'POST');

// Fail2Ban repeated invalid signatures by IP
$config->fail2ban('webhook-invalid', threshold: 3, period: 120, ban: 900,
    filter: fn($req): bool => $signatureInvalid($req),
    key: fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null
);
```

### 8) Protect admin area: block non-private networks + mirror to Apache .htaccess

```php
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Psr\EventDispatcher\EventDispatcherInterface;

// App-level blocklist for /admin if not from private ranges
$config->blocklist('admin-non-private', function ($req): bool {
    $path = $req->getUri()->getPath();
    $ip = $req->getServerParams()['REMOTE_ADDR'] ?? '';
    $isPrivate = str_starts_with($ip, '10.') || str_starts_with($ip, '192.168.') || str_starts_with($ip, '172.16.');
    return str_starts_with($path, '/admin') && !$isPrivate;
});

// Optional: mirror Fail2Ban bans to Apache .htaccess without blocking requests
$adapter = new ApacheHtaccessAdapter('/var/www/app/.htaccess');
$runner = new SyncNonBlockingRunner();
$listener = new InfrastructureBanListener($adapter, $runner, blockOnFail2Ban: true, blockOnBlocklist: false);

// Register $listener methods with your PSR-14 dispatcher
$dispatcher = /* your framework's dispatcher */ null; // pseudo-code
if ($dispatcher instanceof EventDispatcherInterface) {
    // e.g., using a mapping facility in your framework
    // $dispatcher->listen(Fail2BanBanned::class, [$listener, 'onFail2BanBanned']);
}
```

Security notes:
- Treat IP-based decisions carefully when behind proxies (use `TrustedProxyResolver`).
- Prefer Redis for multi-instance deployments.
- Keep handlers fast; use queues or async for heavy tasks.

## OWASP Core Rule Set (CRS) adapter

Phirewall can parse and evaluate a subset of the OWASP Core Rule Set (CRS) syntax to block malicious requests using familiar `SecRule` lines.
This adapter is designed to be safe and performant while covering common operators and variables.

This is not a full CRS implementation; it supports a practical subset suitable for many use cases. Unsupported features are ignored safely.
The implementation focuses on the `deny` action and is still work-in-progress.

See https://coreruleset.org/docs/ for the full CRS project.

### Supported variables

- `REQUEST_URI` — path and query string as a single string
- `REQUEST_METHOD`
- `QUERY_STRING`
- `ARGS` — includes both argument names and values from query and parsed body
- `ARGS_NAMES` — argument names only from query and parsed body
- `REQUEST_HEADERS` — all header values (across all header names)
- `REQUEST_HEADERS_NAMES` — header names only
- `REQUEST_COOKIES`
- `REQUEST_COOKIES_NAMES`

Unsupported variables are ignored for that rule (the rule becomes a no‑op if no supported variables are present).

### Supported operators

All supported string operators are case‑insensitive:
- `@contains` — substring match (case‑insensitive)
- `@streq` — string equality (case‑insensitive)
- `@startswith` / `@beginswith` — prefix match (case‑insensitive)
- `@endswith` — suffix match (case‑insensitive)

Pattern matching:
- `@rx` — PHP PCRE regular expression. Invalid patterns are handled safely and treated as a non‑match (no warnings or errors are emitted).
- `@pm` — phrase match against a list of phrases separated by spaces or newlines. For safety, a cap of 5000 phrases is enforced; phrases beyond the cap are ignored.

Notes:
- Rules act only when they have the `deny` action.
- Evaluation short‑circuits on first match.

### Loaders

Use `SecRuleLoader` to load rules in several convenient ways:

- From a string containing multiple `SecRule` lines:

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

$rulesText = <<<'TXT'
SecRule REQUEST_URI "@rx ^/admin\\b" "id:600001,phase:2,deny,msg:'Block admin path'"
SecRule REQUEST_METHOD "@streq POST" "id:600002,phase:2,deny,msg:'Deny POST'"
TXT;
$coreRuleSet = SecRuleLoader::fromString($rulesText);
```

- From a string with a report of parsed vs skipped items:

```php
$result = SecRuleLoader::fromStringWithReport($rulesText);
// $result = ['rules' => CoreRuleSet, 'parsed' => int, 'skipped' => int]
```

- From multiple files (throws on missing file):

```php
$coreRuleSet = SecRuleLoader::fromFiles(['/path/a.conf', '/path/b.conf']);
```

- From a directory with optional filter and deterministic sorted loading:

```php
$filter = static fn(string $path): bool => str_ends_with($path, '.conf');
$coreRuleSet = SecRuleLoader::fromDirectory('/path/crs', $filter);
```

### Enabling/Disabling specific rule IDs

Every rule has an integer `id`. All rules are enabled by default; you can enable/disable them programmatically:

```php
$coreRuleSet->disable(600002); // disable a rule
$coreRuleSet->enable(600002);  // re‑enable a rule
```

### Integrating CRS with the Firewall

Register the rule set as a blocklist on the `Config`:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());
$config->owaspBlocklist('owasp', $coreRuleSet);

$firewall = new Firewall($config);
$response = $firewall->decide($request);
```

The `FirewallResult` will include standard blocklist headers when a rule matches.

### Optional diagnostics header (OFF by default)

For troubleshooting, you can opt‑in to emit an additional header with the matched OWASP rule id:

- Header: `X-Phirewall-Owasp-Rule: <rule-id>`
- Default: OFF

Enable once on your configuration:

```php
$config->enableOwaspDiagnosticsHeader(true);
```

When enabled and an OWASP rule blocks a request, the header is included in the result headers.

### Safety and performance

- Invalid `@rx` patterns are treated as no‑match without throwing.
- `@pm` and `@pmFromFile` enforce a maximum phrases cap (currently 5000) to prevent pathological inputs.
- Evaluation uses short‑circuiting to stop at the first positive match.
- Matching for string operators is case‑insensitive for consistency across variables (URI, headers, etc.).

### Example minimal rule

```apache
SecRule REQUEST_URI "@rx ^/admin\\b" "id:600001,phase:2,deny,msg:'Block admin path'"
```

With the above rule loaded and the diagnostics header enabled, requests to `/admin` will be blocked and include `X-Phirewall-Owasp-Rule: 600001`.

## Examples

Real-world configuration snippets are available in the examples directory. Each script is intended to be run directly via CLI (they throw if included) so that CI jobs can execute them and ensure they stay functional:

- `php examples/api_rate_limiting.php`
- `php examples/login_protection.php`
- `php examples/ip_banlists.php`
- `php examples/redis_setup.php`
- `php examples/observability_monolog.php`
- `php examples/observability_opentelemetry.php`
- `php examples/owasp_crs_basic.php`
- `php examples/benchmarks_counters.php`

These scripts showcase:
- API-wide rate limiting and per-route buckets
- Login protection with track/fail2ban/throttle
- File/IP blocklists, pattern backends, and infrastructure adapters
- Redis/APCu/in-memory counter stores
- Observability hooks (Monolog, OpenTelemetry)

## Development

- Run code fixes: `composer fix`
- Run tests and code analysis: `composer test`
- Mutation testing (optional): `composer test:mutation`
  - With coverage pre-enabled: `composer test:mutation:coverage`
  - Reports are written to `.build/infection.html` and logs under `.build/`

## Sponsors
This project received funding from TYPO3 Association by its Community Budget program.
https://typo3.org/article/members-have-selected-four-ideas-to-be-funded-in-quarter-4-2025

## License
This software package (“the Software”) is made available under a dual license. See the LICENSE file for details.
