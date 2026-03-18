# Configuration Reference

This document covers all configuration options available in Phirewall.

## Config Class

The `Config` class is the central configuration object for Phirewall.

### Constructor

```php
use Flowd\Phirewall\Config;
use Psr\SimpleCache\CacheInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

public function __construct(
    CacheInterface $cache,
    ?EventDispatcherInterface $eventDispatcher = null
)
```

**Parameters:**
- `$cache` - Any PSR-16 compatible cache for storing counters and ban states
- `$eventDispatcher` - Optional PSR-14 event dispatcher for observability

**Example:**
```php
$config = new Config(new InMemoryCache());

// With event dispatcher
$config = new Config(new RedisCache($redis), $eventDispatcher);
```

---

## Rule Methods

### safelist()

Define a safelist rule that bypasses all other checks.

```php
public function safelist(string $name, Closure $callback): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$callback` - `fn(ServerRequestInterface): bool` - Return `true` to safelist

**Example:**
```php
$config->safelist('health', fn($req) => $req->getUri()->getPath() === '/health');

$config->safelist('internal-ip', function ($req): bool {
    $ip = $req->getServerParams()['REMOTE_ADDR'] ?? '';
    return str_starts_with($ip, '10.') || str_starts_with($ip, '192.168.');
});
```

---

### blocklist()

Define a blocklist rule that denies requests with 403 Forbidden.

```php
public function blocklist(string $name, Closure $callback): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$callback` - `fn(ServerRequestInterface): bool` - Return `true` to block

**Example:**
```php
$config->blocklist('wp-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/wp-admin'));

$config->blocklist('bad-ips', function ($req): bool {
    $badIps = ['1.2.3.4', '5.6.7.8'];
    $ip = $req->getServerParams()['REMOTE_ADDR'] ?? '';
    return in_array($ip, $badIps, true);
});
```

---

### throttle()

Define a rate limiting rule that returns 429 Too Many Requests when exceeded.

```php
public function throttle(string $name, int $limit, int $period, Closure $key): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$limit` - Maximum requests allowed in the period
- `$period` - Time window in seconds
- `$key` - `fn(ServerRequestInterface): ?string` - Return a key to group requests, or `null` to skip

**Example:**
```php
// 100 requests per minute per IP
$config->throttle('ip-limit', limit: 100, period: 60, key: KeyExtractors::ip());

// Per-endpoint limit
$config->throttle('search-limit', limit: 20, period: 60, key: function ($req): ?string {
    if ($req->getUri()->getPath() === '/api/search') {
        return $req->getServerParams()['REMOTE_ADDR'] ?? null;
    }
    return null; // Skip other paths
});

// Per-user limit
$config->throttle('user-limit', limit: 1000, period: 3600, key: KeyExtractors::header('X-User-Id'));
```

---

### fail2ban()

Define a Fail2Ban rule that bans keys after repeated filter matches.

```php
public function fail2ban(
    string $name,
    int $threshold,
    int $period,
    int $ban,
    Closure $filter,
    Closure $key
): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$threshold` - Number of filter matches before ban
- `$period` - Time window for counting matches (seconds)
- `$ban` - Ban duration (seconds)
- `$filter` - `fn(ServerRequestInterface): bool` - Return `true` to count as failure
- `$key` - `fn(ServerRequestInterface): ?string` - Return key to track, or `null` to skip

**Example:**
```php
// Ban after 5 failed logins in 5 minutes, for 1 hour
$config->fail2ban('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

// Ban after 3 invalid API signatures in 2 minutes, for 15 minutes
$config->fail2ban('api-abuse',
    threshold: 3,
    period: 120,
    ban: 900,
    filter: fn($req) => $req->getHeaderLine('X-Signature-Invalid') === '1',
    key: function ($req): ?string {
        return $req->getHeaderLine('X-API-Key') ?: $req->getServerParams()['REMOTE_ADDR'];
    }
);
```

---

### allow2ban

Define an Allow2Ban rule that bans keys after exceeding a total request threshold. Unlike Fail2Ban, Allow2Ban counts **all** requests for a key -- no filter is needed.

```php
$config->allow2ban->add(
    string $name,
    int $threshold,
    int $period,
    int $banSeconds,
    Closure $key
): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$threshold` - Number of requests allowed before ban
- `$period` - Time window for counting requests (seconds)
- `$banSeconds` - Ban duration (seconds)
- `$key` - `fn(ServerRequestInterface): ?string` - Return key to track, or `null` to skip

**When to use allow2ban vs fail2ban vs throttle:**
- Use **throttle** when you want to rate-limit with a `429 Too Many Requests` response and a `Retry-After` header -- the client is expected to retry later.
- Use **fail2ban** when you want to ban based on specific "bad" requests (e.g. failed logins) that match a filter predicate.
- Use **allow2ban** when you want a hard volume cap that bans the key entirely after a threshold -- no filter needed, every request counts.

**Example:**
```php
// Ban any IP that sends more than 100 requests in 60 seconds, for 1 hour
$config->allow2ban->add('high-volume-ban',
    threshold: 100,
    period: 60,
    banSeconds: 3600,
    key: KeyExtractors::ip()
);

// Ban by API key after 1000 requests per minute, for 5 minutes
$config->allow2ban->add('api-key-ban',
    threshold: 1000,
    period: 60,
    banSeconds: 300,
    key: KeyExtractors::header('X-Api-Key')
);
```

#### Throttle vs Fail2Ban vs Allow2Ban

| Feature | Throttle | Fail2Ban | Allow2Ban |
|---------|----------|----------|-----------|
| Counts | All requests | Filtered requests only | All requests |
| Response | 429 + Retry-After | Block | Block |
| Use case | Rate limiting | Abuse pattern detection | Hard volume cap |
| Filter needed | No | Yes | No |

---

### track()

Define a tracking rule for passive counting without blocking.

```php
public function track(string $name, int $period, Closure $filter, Closure $key): self
```

**Parameters:**
- `$name` - Unique rule identifier
- `$period` - Time window for counting (seconds)
- `$filter` - `fn(ServerRequestInterface): bool` - Return `true` to count
- `$key` - `fn(ServerRequestInterface): ?string` - Return key to track, or `null` to skip

**Example:**
```php
// Track login failures for observability
$config->track('login-failures', period: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

// Track 404 errors by path
$config->track('not-found', period: 600,
    filter: fn($req) => $req->getHeaderLine('X-Response-Status') === '404',
    key: KeyExtractors::path()
);
```

---

## Pattern Backends

Pattern backends store blocklist entries (IPs, CIDRs, paths, headers) with optional expiration. For detailed documentation, see [Pattern Backends](pattern-backends.md).

### inMemoryPatternBackend()

Create an in-memory pattern backend for configuration-based blocklists.

```php
public function inMemoryPatternBackend(string $name, array $entries = []): InMemoryPatternBackend
```

**Example:**
```php
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

$backend = $config->inMemoryPatternBackend('private-networks', [
    new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
    new PatternEntry(PatternKind::CIDR, '192.168.0.0/16'),
    new PatternEntry(PatternKind::IP, '127.0.0.1'),
]);

$config->blocklistFromBackend('block-private', 'private-networks');
```

---

### filePatternBackend()

Create a file-backed pattern storage.

```php
public function filePatternBackend(string $name, string $filePath): FilePatternBackend
```

**Example:**
```php
$backend = $config->filePatternBackend('blocklist', '/var/lib/phirewall/blocklist.txt');

// Add patterns
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '1.2.3.4',
    expiresAt: time() + 3600, // 1 hour
));

$backend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '192.168.0.0/24',
));
```

---

### blocklistFromBackend()

Register a pattern backend as a blocklist.

```php
public function blocklistFromBackend(string $name, string $backendName): self
```

**Example:**
```php
$config->filePatternBackend('bad-actors', '/var/lib/phirewall/bad-actors.txt');
$config->blocklistFromBackend('bad-actors-blocklist', 'bad-actors');
```

---

### fileIpBlocklist()

Convenience method for file-backed IP blocklists.

```php
public function fileIpBlocklist(
    string $name,
    string $filePath,
    ?callable $ipResolver = null
): FileIpBlocklistStore
```

**Example:**
```php
$store = $config->fileIpBlocklist('banned-ips', '/var/lib/phirewall/banned.txt');

// Add IPs programmatically
$store->append('1.2.3.4');
```

---

## OWASP Integration

### owaspBlocklist()

Register OWASP Core Rule Set rules as a blocklist.

```php
public function owaspBlocklist(string $name, CoreRuleSet $coreRuleSet): self
```

**Example:**
```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

// Load from directory
$crs = SecRuleLoader::fromDirectory('/path/to/crs');
$config->owaspBlocklist('owasp', $crs);

// Load from string
$rules = <<<'CRS'
SecRule REQUEST_URI "@rx /admin" "id:1001,phase:2,deny,msg:'Block admin'"
CRS;
$crs = SecRuleLoader::fromString($rules);
$config->owaspBlocklist('custom', $crs);
```

---

## Response Customization

### blocklistedResponse()

Customize the response for blocked requests.

```php
public function blocklistedResponse(Closure $factory): self
```

**Closure signature:**
```php
fn(string $rule, string $type, ServerRequestInterface $request): ResponseInterface
```

**Parameters:**
- `$rule` - The rule name that triggered
- `$type` - The block type: `blocklist` or `fail2ban`
- `$request` - The original request

**Example:**
```php
$config->blocklistedResponse(function (string $rule, string $type, $req): ResponseInterface {
    return new Response(403, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'Access Denied',
        'rule' => $rule,
        'type' => $type,
    ]));
});
```

---

### throttledResponse()

Customize the response for throttled requests.

```php
public function throttledResponse(Closure $factory): self
```

**Closure signature:**
```php
fn(string $rule, int $retryAfter, ServerRequestInterface $request): ResponseInterface
```

**Example:**
```php
$config->throttledResponse(function (string $rule, int $retryAfter, $req): ResponseInterface {
    return new Response(429, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'Rate limit exceeded',
        'retry_after' => $retryAfter,
    ]));
});
```

---

## Global Options

### enableRateLimitHeaders()

Enable standard X-RateLimit-* headers on responses.

```php
public function enableRateLimitHeaders(bool $enabled = true): self
```

**Headers emitted:**
- `X-RateLimit-Limit` - Configured limit
- `X-RateLimit-Remaining` - Remaining requests
- `X-RateLimit-Reset` - Seconds until reset

**Example:**
```php
$config->enableRateLimitHeaders();
```

---

### enableOwaspDiagnosticsHeader()

Enable OWASP rule ID header for debugging.

```php
public function enableOwaspDiagnosticsHeader(bool $enabled = true): self
```

**Header emitted:**
- `X-Phirewall-Owasp-Rule` - Matched rule ID

**Example:**
```php
$config->enableOwaspDiagnosticsHeader(); // Only in development!
```

---

### setKeyPrefix()

Set a global prefix for all cache keys.

```php
public function setKeyPrefix(string $prefix): self
```

**Default:** `phirewall`

**Example:**
```php
$config->setKeyPrefix('myapp');
// Keys become: myapp:throttle:..., myapp:fail2ban:..., etc.
```

---

## KeyExtractors Helper

Common key extractors for throttles, fail2ban, and track rules.

### ip()

Extract IP from REMOTE_ADDR (no proxy trust).

```php
KeyExtractors::ip()
```

### clientIp()

Extract IP using trusted proxy resolver.

```php
KeyExtractors::clientIp(TrustedProxyResolver $resolver)
```

### header()

Extract value from a specific header.

```php
KeyExtractors::header(string $name)
```

### method()

Extract HTTP method (uppercase).

```php
KeyExtractors::method()
```

### path()

Extract request path.

```php
KeyExtractors::path()
```

### userAgent()

Extract User-Agent header.

```php
KeyExtractors::userAgent()
```

---

## TrustedProxyResolver

Securely resolve client IPs behind trusted proxies.

### Constructor

```php
public function __construct(
    array $trustedProxies,
    array $allowedHeaders = ['X-Forwarded-For', 'Forwarded'],
    int $maxChainEntries = 50
)
```

**Parameters:**
- `$trustedProxies` - List of trusted IP addresses or CIDR ranges
- `$allowedHeaders` - Headers to check for client IP
- `$maxChainEntries` - Maximum chain length to prevent header injection

**Example:**
```php
$resolver = new TrustedProxyResolver([
    '127.0.0.1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '2001:db8::/32',  // IPv6 support
]);

$clientIp = $resolver->resolve($request);
```

---

## Pattern Entry Types

Available pattern kinds for pattern backends:

| Kind | Description | Example |
|------|-------------|---------|
| `PatternKind::IP` | Exact IP match | `192.168.1.100` |
| `PatternKind::CIDR` | CIDR range match | `10.0.0.0/8` |
| `PatternKind::PATH_EXACT` | Exact path match | `/admin` |
| `PatternKind::PATH_PREFIX` | Path prefix match | `/api/` |
| `PatternKind::PATH_REGEX` | Path regex match | `/^\/user\/\d+$/` |
| `PatternKind::HEADER_EXACT` | Exact header value | `Bot` (User-Agent) |
| `PatternKind::HEADER_REGEX` | Header value regex | `/bot|crawler/i` |
| `PatternKind::REQUEST_REGEX` | Full request regex | `/sql.*injection/i` |

**Example:**
```php
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

$backend->append(new PatternEntry(
    kind: PatternKind::HEADER_REGEX,
    value: '/sqlmap|nikto|nmap/i',
    target: 'User-Agent',
    expiresAt: null,  // Never expires
    addedAt: time(),
    metadata: ['reason' => 'Scanner detected'],
));
```

---

## Diagnostics

### getDiagnosticsCounters()

Get lightweight per-category counters.

```php
public function getDiagnosticsCounters(): array
```

**Returns:**
```php
[
    'safelisted' => ['total' => 10, 'by_rule' => ['health' => 8, 'metrics' => 2]],
    'blocklisted' => ['total' => 5, 'by_rule' => ['scanners' => 5]],
    'throttle_exceeded' => ['total' => 2, 'by_rule' => ['ip-limit' => 2]],
    'passed' => ['total' => 1000, 'by_rule' => []],
]
```

### resetDiagnosticsCounters()

Reset all diagnostics counters.

```php
public function resetDiagnosticsCounters(): void
```
