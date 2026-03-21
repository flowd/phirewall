# Storage Backends

Phirewall uses PSR-16 (Simple Cache) compatible backends for storing counters and ban states. This document covers all available backends and how to choose the right one.

## Quick Comparison

| Backend | Persistence | Distribution | Performance | Use Case |
|---------|-------------|--------------|-------------|----------|
| InMemoryCache | No | No | Fastest | Testing, single-request scripts |
| ApcuCache | Process restart | No | Very Fast | Single-server production |
| RedisCache | Yes | Yes | Fast | Multi-server production |
| PdoCache | Yes | Shared DB* | Moderate | SQL-backed persistence without Redis |
| Any PSR-16 | Varies | Varies | Varies | Custom integrations |

---

## InMemoryCache

A simple in-memory cache ideal for testing and development.

### Characteristics

- **Persistence:** None (lost after request)
- **Distribution:** Single process only
- **Atomicity:** Non-atomic (adequate for testing)
- **Dependencies:** None

### Usage

```php
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
$config = new Config($cache);
```

### With Custom Clock (Testing)

```php
use Flowd\Phirewall\Store\ClockInterface;

// For time-dependent tests
$clock = new class implements ClockInterface {
    private float $time;
    public function __construct() { $this->time = microtime(true); }
    public function now(): float { return $this->time; }
    public function advance(int $seconds): void { $this->time += $seconds; }
};

$cache = new InMemoryCache($clock);

// In tests, advance time
$clock->advance(60); // Move forward 60 seconds
```

### When to Use

- Unit tests
- Integration tests
- Development environments
- Single-script CLI tools

### When NOT to Use

- Production web applications (counters reset each request in PHP-FPM)
- Multi-server deployments
- Any scenario requiring persistence

---

## ApcuCache

High-performance in-process cache using the APCu extension.

### Characteristics

- **Persistence:** Survives between requests (until process restart)
- **Distribution:** Single server only
- **Atomicity:** Atomic increments via `apcu_inc()`
- **Dependencies:** `ext-apcu`

### Installation

```bash
# Install APCu extension
pecl install apcu

# Enable in php.ini
extension=apcu.so
apc.enable_cli=1  # Required for CLI testing
```

### Usage

```php
use Flowd\Phirewall\Store\ApcuCache;

$cache = new ApcuCache();
$config = new Config($cache);
```

### Verification

```php
if (!function_exists('apcu_enabled') || !apcu_enabled()) {
    throw new RuntimeException('APCu is not available');
}
```

### When to Use

- Single-server production
- High-traffic applications needing fast counters
- Shared hosting (if APCu is available)

### When NOT to Use

- Multi-server deployments (counters not shared)
- Environments without APCu
- When persistence across restarts is required

### Performance Tuning

```ini
; php.ini settings
apc.shm_size=128M      ; Shared memory size
apc.ttl=0              ; No automatic expiration
apc.gc_ttl=3600        ; Garbage collection TTL
```

---

## RedisCache

Distributed cache using Redis via the Predis client.

### Characteristics

- **Persistence:** Yes (survives restarts with proper Redis config)
- **Distribution:** Full multi-server support
- **Atomicity:** Atomic via Lua scripts
- **Dependencies:** `predis/predis`

### Installation

```bash
composer require predis/predis
```

### Basic Usage

```php
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis);
$config = new Config($cache);
```

### With Custom Namespace

```php
// Namespace all keys with a prefix
$cache = new RedisCache($redis, 'myapp:firewall:');

// Keys will be: myapp:firewall:phirewall:throttle:...
```

### Connection Options

```php
// TCP connection
$redis = new PredisClient([
    'scheme' => 'tcp',
    'host' => 'redis.example.com',
    'port' => 6379,
    'password' => 'secret',
    'database' => 1,
]);

// Unix socket
$redis = new PredisClient([
    'scheme' => 'unix',
    'path' => '/var/run/redis/redis.sock',
]);

// Cluster
$redis = new PredisClient([
    ['host' => 'node1.example.com', 'port' => 6379],
    ['host' => 'node2.example.com', 'port' => 6379],
], ['cluster' => 'redis']);

// Sentinel
$redis = new PredisClient([
    ['host' => 'sentinel1.example.com', 'port' => 26379],
    ['host' => 'sentinel2.example.com', 'port' => 26379],
], [
    'replication' => 'sentinel',
    'service' => 'mymaster',
]);
```

### Fail-Open Behavior

RedisCache is designed to fail open:

```php
// If Redis is unavailable, increment() returns 0
// This allows your application to decide how to handle the failure

$count = $cache->increment('key', 60);
if ($count === 0) {
    // Redis might be down
    // Either allow the request or use a fallback
}
```

### When to Use

- Multi-server production deployments
- When counters must be shared across instances
- When persistence is required
- Kubernetes/Docker deployments

### When NOT to Use

- Simple single-server setups (APCu is faster)
- When Redis infrastructure is not available
- Cost-sensitive environments (Redis requires separate service)

### Performance Tuning

```ini
; Redis server configuration
maxmemory 256mb
maxmemory-policy volatile-ttl  ; Evict keys with TTL first
```

---

## PdoCache

SQL-backed cache using PDO for MySQL, PostgreSQL, or SQLite.

### Characteristics

- **Persistence:** Yes (stored in database)
- **Distribution:** Yes, when multiple servers share the same MySQL/PostgreSQL database. SQLite is local only.
- **Atomicity:** Transactional increments via `BEGIN`/`COMMIT`
- **Dependencies:** `ext-pdo` (bundled with PHP)

### Basic Usage

```php
use Flowd\Phirewall\Store\PdoCache;

// SQLite (file-based, zero-config)
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$cache = new PdoCache($pdo);
$config = new Config($cache);

// MySQL
$pdo = new PDO('mysql:host=localhost;dbname=myapp', 'user', 'password');
$cache = new PdoCache($pdo);
$config = new Config($cache);

// PostgreSQL
$pdo = new PDO('pgsql:host=localhost;dbname=myapp', 'user', 'password');
$cache = new PdoCache($pdo);
$config = new Config($cache);
```

### Custom Table Name

```php
// Use a custom table name (alphanumeric and underscores only)
$cache = new PdoCache($pdo, 'my_app_firewall_cache');
```

The table is auto-created on first use with the schema:

```sql
CREATE TABLE IF NOT EXISTS phirewall_cache (
    cache_key VARCHAR(255) NOT NULL PRIMARY KEY,
    cache_value TEXT NOT NULL,
    expires_at INTEGER NULL
);
```

### Features

- **Auto-pruning:** Expired entries are probabilistically cleaned up (1% of reads)
- **Table name validation:** Only safe alphanumeric names are accepted (prevents SQL injection)
- **Prepared statements:** All queries use parameterized statements
- **Upsert support:** SQLite (`INSERT OR REPLACE`), PostgreSQL (`ON CONFLICT`), MySQL (`ON DUPLICATE KEY`)

### When to Use

- Environments where only a SQL database is available (no Redis, no APCu)
- Applications that already use a relational database
- SQLite for lightweight single-server setups
- Staging/development with persistence needs

### When NOT to Use

- High-traffic production (Redis or APCu are significantly faster)
- Multi-server deployments without a shared database
- Applications where microsecond latency matters

### Performance Tips

- Add an index on `expires_at` for faster pruning on large tables
- Use SQLite WAL mode for better concurrent read performance
- Consider a dedicated database/schema to avoid polluting application tables

```php
// Enable SQLite WAL mode
$pdo = new PDO('sqlite:/var/lib/phirewall/cache.db');
$pdo->exec('PRAGMA journal_mode=WAL');
$cache = new PdoCache($pdo);
```

### Using with Doctrine DBAL

If your application already uses Doctrine DBAL, you can pass its native PDO connection directly to PdoCache — no additional dependencies required:

```php
use Doctrine\DBAL\DriverManager;
use Flowd\Phirewall\Store\PdoCache;

$dbalConnection = DriverManager::getConnection(['url' => 'mysql://user:pass@localhost/myapp']);

// Get the underlying PDO instance from DBAL
$pdo = $dbalConnection->getNativeConnection();
assert($pdo instanceof \PDO);

$cache = new PdoCache($pdo);
$config = new Config($cache);
```

This lets you reuse your existing database connection and configuration without adding `doctrine/dbal` as a dependency of Phirewall itself.

---

## Using Any PSR-16 Cache

Phirewall works with any PSR-16 compatible cache.

### Symfony Cache

```php
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\Cache\Psr16Cache;

$redisAdapter = RedisAdapter::createConnection('redis://localhost');
$cache = new Psr16Cache(new RedisAdapter($redisAdapter));
$config = new Config($cache);
```

### Laravel Cache

```php
use Illuminate\Cache\Repository;
use Illuminate\Cache\ArrayStore;

// Note: Laravel's cache implements PSR-16 via getStore()
$laravelCache = app('cache')->store('redis');

// Wrap if needed for PSR-16 compliance
$config = new Config($laravelCache);
```

### Doctrine Cache

```php
use Doctrine\Common\Cache\Psr6\DoctrineProvider;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

$psr6Cache = new ArrayAdapter();
$cache = new Psr16Cache($psr6Cache);
$config = new Config($cache);
```

### Limitations

When using generic PSR-16 caches without `CounterStoreInterface`:

- Counter increments are non-atomic (race conditions possible)
- TTL remaining calculations may be less accurate
- Fixed-window alignment may drift slightly

For production, prefer the bundled `RedisCache` or `ApcuCache`.

---

## CounterStoreInterface

Phirewall's caches implement `CounterStoreInterface` for accurate fixed-window rate limiting.

```php
interface CounterStoreInterface
{
    /**
     * Atomically increment a counter with window-aligned expiry.
     *
     * @param string $key    Counter key
     * @param int    $period Window size in seconds
     * @return int           New counter value
     */
    public function increment(string $key, int $period): int;

    /**
     * Get remaining TTL for a key.
     *
     * @param string $key Counter key
     * @return int        Seconds remaining (0 if expired/missing)
     */
    public function ttlRemaining(string $key): int;
}
```

### Benefits

- **Atomic increments:** No race conditions
- **Window alignment:** Counters reset at predictable times
- **Accurate TTL:** Precise Retry-After headers

---

## Choosing the Right Backend

### Decision Tree

```
Testing or development?
├── Yes → InMemoryCache (no setup, deterministic with FakeClock)
└── No (production)
    └── Multiple application servers?
        ├── Yes
        │   └── What is available?
        │       ├── Redis → RedisCache (fastest distributed option, atomic Lua scripts)
        │       └── Shared MySQL/PostgreSQL → PdoCache (no extra services needed)
        └── No (single server)
            └── What is your priority?
                ├── Maximum performance
                │   └── APCu available?
                │       ├── Yes → ApcuCache (fastest, in-process, atomic)
                │       └── No → RedisCache or PdoCache
                ├── Persistence across restarts
                │   └── Database already available?
                │       ├── Yes → PdoCache (no extra infrastructure)
                │       └── No → RedisCache or PdoCache with SQLite
                └── Minimal dependencies
                    └── PdoCache with SQLite (zero-config, file-based)
```

**Key trade-offs:**
- **ApcuCache** is fastest but data is lost on process restart (PHP-FPM reload, deploy). Fine when losing counters briefly is acceptable.
- **RedisCache** is the most capable (distributed, persistent, atomic) but requires a Redis service.
- **PdoCache** needs no extra infrastructure if you already have a database. With MySQL/PostgreSQL it supports multi-server deployments. Slower than Redis under high concurrency.
- **InMemoryCache** resets every request in PHP-FPM — only useful for testing or single-run CLI scripts.

### Environment Recommendations

| Environment | Recommended Backend | Notes |
|-------------|---------------------|-------|
| Unit Tests | InMemoryCache | Use FakeClock for deterministic time |
| Integration Tests | InMemoryCache or RedisCache | Redis via Docker for realistic testing |
| Development | InMemoryCache or PdoCache (SQLite) | SQLite if you want persistence during dev |
| Single Server (high traffic) | ApcuCache | Fastest option; counters lost on restart |
| Single Server (existing DB) | PdoCache | No extra services; persistent |
| Single Server (no infra) | PdoCache (SQLite) | Zero-config, file-based persistence |
| Multiple Servers | RedisCache or PdoCache | Redis preferred; PdoCache works with shared DB |
| Kubernetes / Docker | RedisCache | Shared state across pods |
| Serverless (Lambda) | RedisCache (external) | No local state between invocations |
| Shared Hosting | ApcuCache or PdoCache | Depends on what's available |

---

## Cache Key Structure

Understanding the key structure helps with debugging and monitoring.

### Key Format

```
{config_prefix}:{type}:{rule}:{key}
```

### Examples

```
phirewall:throttle:ip-limit:192.168.1.100
phirewall:fail2ban:fail:login:192.168.1.100
phirewall:fail2ban:ban:login:192.168.1.100
phirewall:track:api-calls:user-123
```

### Key Normalization

Keys are automatically normalized:
- Only `A-Za-z0-9._:-` characters allowed
- Other characters replaced with `_`
- Long keys truncated with SHA-1 suffix

---

## Monitoring Cache Usage

### Redis

```bash
# Watch keys in real-time
redis-cli monitor | grep phirewall

# Count keys
redis-cli keys "phirewall:*" | wc -l

# Check memory usage
redis-cli info memory

# Get specific key
redis-cli get "phirewall:throttle:ip-limit:192.168.1.100"
```

### APCu

```php
// Get cache info
$info = apcu_cache_info();

// Get all Phirewall keys
$iterator = new APCuIterator('/^phirewall:/');
foreach ($iterator as $item) {
    echo $item['key'] . ': ' . $item['value'] . "\n";
}
```

### PdoCache

```sql
-- Count all entries
SELECT COUNT(*) FROM phirewall_cache;

-- List all active (non-expired) keys
SELECT cache_key, expires_at
FROM phirewall_cache
WHERE expires_at IS NULL OR expires_at > UNIX_TIMESTAMP();

-- Prune expired entries manually
DELETE FROM phirewall_cache
WHERE expires_at IS NOT NULL AND expires_at <= UNIX_TIMESTAMP();

-- For SQLite, use strftime('%s', 'now') instead of UNIX_TIMESTAMP()
```
