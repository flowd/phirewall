# Pattern Backends

Pattern backends provide a flexible way to manage dynamic blocklists with support for various pattern types (IPs, CIDRs, paths, headers, regex) and optional expiration.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Config                                   │
│                                                                  │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │ Pattern Backend  │────▶│ blocklistFromBackend('name', ..) │  │
│  │ (stores entries) │     │ (registers as blocklist rule)    │  │
│  └──────────────────┘     └──────────────────────────────────┘  │
│           │                            │                         │
│           ▼                            ▼                         │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │ PatternSnapshot  │────▶│ SnapshotBlocklistMatcher         │  │
│  │ (point-in-time)  │     │ (evaluates requests)             │  │
│  └──────────────────┘     └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **PatternBackendInterface** | Storage interface for pattern entries |
| **PatternEntry** | Single pattern with kind, value, expiration, metadata |
| **PatternKind** | Type of pattern (IP, CIDR, path, header, regex) |
| **PatternSnapshot** | Immutable point-in-time view of entries |
| **SnapshotBlocklistMatcher** | Evaluates requests against snapshot |

---

## Pattern Backends

### InMemoryPatternBackend

Stores patterns in memory. Ideal for:
- Configuration-based blocklists (hardcoded in PHP)
- Testing and development
- Entries loaded from external sources at startup

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

$config = new Config($cache);

// Simple: One-step creation and registration
$backend = $config->patternBlocklist('private-networks', [
    new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
    new PatternEntry(PatternKind::CIDR, '192.168.0.0/16'),
    new PatternEntry(PatternKind::IP, '203.0.113.50'),
]);

// The backend is returned so you can add more entries later
$backend->append(new PatternEntry(PatternKind::IP, '203.0.113.51'));
```

**Alternative: Two-step approach** (useful when sharing a backend between rules):
```php
$backend = $config->inMemoryPatternBackend('blocked-ranges', [...]);
$config->blocklistFromBackend('rule-name', 'blocked-ranges');
```

**Characteristics:**
- No file I/O
- Entries lost when process ends
- Fast reads (no disk access)
- Supports all pattern kinds

### FilePatternBackend

Stores patterns in a text file. Ideal for:
- Persistent blocklists
- External tools updating the blocklist
- Sharing blocklists across processes

```php
// Simple: One-step creation and registration
$backend = $config->filePatternBlocklist('dynamic-blocks', '/var/lib/phirewall/blocks.txt');

// Add entries (persisted to file)
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.100',
    expiresAt: time() + 3600,  // 1 hour
));
```

**Alternative: Two-step approach:**
```php
$backend = $config->filePatternBackend('dynamic-blocks', '/path/to/file.txt');
$config->blocklistFromBackend('rule-name', 'dynamic-blocks');
```

**Characteristics:**
- Persists across restarts
- Atomic file writes (safe for concurrent access)
- External tools can modify the file
- Automatic duplicate handling

**File Format:**
```
# Comments start with # or ;
ip|1.2.3.4|||1704067200|1704063600
cidr|10.0.0.0/8||||
path_prefix|/admin||||
header_regex|/bot/i|User-Agent|||
```

Fields: `kind|value|target|expiresAt|addedAt`

---

## Pattern Entry

A `PatternEntry` represents a single blocking pattern.

```php
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

$entry = new PatternEntry(
    kind: PatternKind::CIDR,           // Pattern type
    value: '10.0.0.0/8',               // Pattern value
    target: null,                       // Target field (for header patterns)
    expiresAt: time() + 3600,          // Unix timestamp or null (permanent)
    addedAt: time(),                   // When added (auto-set if null)
    metadata: ['reason' => 'Abuse'],   // Optional metadata
);
```

### Constructor Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `kind` | `string` | Pattern type (use `PatternKind` constants) |
| `value` | `string` | The pattern to match |
| `target` | `?string` | Target field for header patterns (e.g., `'User-Agent'`) |
| `expiresAt` | `?int` | Unix timestamp when entry expires, or `null` for permanent |
| `addedAt` | `?int` | Unix timestamp when added (auto-set if not provided) |
| `metadata` | `array` | Optional key-value metadata for diagnostics |

---

## Pattern Kinds

The `PatternKind` class defines all supported pattern types.

### IP Patterns

#### PatternKind::IP
Matches exact IP addresses.

```php
new PatternEntry(PatternKind::IP, '203.0.113.50')
```

Matches: `203.0.113.50`
Does not match: `203.0.113.51`, `203.0.113.0`

#### PatternKind::CIDR
Matches IP ranges using CIDR notation.

```php
new PatternEntry(PatternKind::CIDR, '10.0.0.0/8')
new PatternEntry(PatternKind::CIDR, '192.168.1.0/24')
new PatternEntry(PatternKind::CIDR, '2001:db8::/32')  // IPv6
```

Matches any IP within the range.

### Path Patterns

#### PatternKind::PATH_EXACT
Matches exact request paths.

```php
new PatternEntry(PatternKind::PATH_EXACT, '/admin')
new PatternEntry(PatternKind::PATH_EXACT, '/.env')
```

Matches: `/admin` (exact)
Does not match: `/admin/users`, `/administrator`

#### PatternKind::PATH_PREFIX
Matches paths starting with a prefix.

```php
new PatternEntry(PatternKind::PATH_PREFIX, '/wp-')
new PatternEntry(PatternKind::PATH_PREFIX, '/api/internal/')
```

Matches: `/wp-admin`, `/wp-login.php`, `/wp-content/`
Does not match: `/wordpress`, `/my-wp-site`

#### PatternKind::PATH_REGEX
Matches paths using regular expressions.

```php
new PatternEntry(PatternKind::PATH_REGEX, '/\.(git|svn|hg)/')
new PatternEntry(PatternKind::PATH_REGEX, '/^\/user\/\d+$/')
```

Uses PCRE regex syntax with delimiters.

### Header Patterns

Header patterns require the `target` parameter to specify which header to match.

#### PatternKind::HEADER_EXACT
Matches exact header values.

```php
new PatternEntry(
    kind: PatternKind::HEADER_EXACT,
    value: '',  // Empty User-Agent
    target: 'User-Agent'
)

new PatternEntry(
    kind: PatternKind::HEADER_EXACT,
    value: 'BadBot/1.0',
    target: 'User-Agent'
)
```

#### PatternKind::HEADER_REGEX
Matches header values using regex.

```php
new PatternEntry(
    kind: PatternKind::HEADER_REGEX,
    value: '/sqlmap|nikto|nmap|masscan/i',
    target: 'User-Agent'
)

new PatternEntry(
    kind: PatternKind::HEADER_REGEX,
    value: '/spam-domain\.com/i',
    target: 'Referer'
)
```

### Request Patterns

#### PatternKind::REQUEST_REGEX
Matches against the full request (method + path + query).

```php
new PatternEntry(
    kind: PatternKind::REQUEST_REGEX,
    value: '/union\s+select/i'
)
```

Useful for complex patterns that span multiple request parts.

---

## How Pattern Matching Works

### SnapshotBlocklistMatcher

When you call `blocklistFromBackend()`, Phirewall creates a `SnapshotBlocklistMatcher` that:

1. **Takes a snapshot** of the backend's entries (via `consume()`)
2. **Caches the snapshot** to avoid repeated reads
3. **Evaluates requests** against all patterns in the snapshot
4. **Refreshes periodically** when the backend indicates changes

```php
// Internal flow (you don't call this directly)
$snapshot = $backend->consume();  // Get current entries
$matcher = new SnapshotBlocklistMatcher($backend);

// On each request
if ($matcher->matches($request)) {
    // Request blocked
}
```

### Snapshot Refresh

The snapshot is refreshed when:
- The backend's version/mtime changes
- A configurable TTL expires (prevents stale data)

This design ensures:
- Fast request evaluation (no I/O per request)
- Changes to backends are picked up automatically
- Multiple processes can share a file backend

---

## Common Use Cases

### Block Private Networks

```php
$backend = $config->inMemoryPatternBackend('private', [
    new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
    new PatternEntry(PatternKind::CIDR, '172.16.0.0/12'),
    new PatternEntry(PatternKind::CIDR, '192.168.0.0/16'),
    new PatternEntry(PatternKind::IP, '127.0.0.1'),
]);
$config->blocklistFromBackend('block-private', 'private');
```

### Block Scanner User-Agents

```php
$backend = $config->inMemoryPatternBackend('scanners', [
    new PatternEntry(
        kind: PatternKind::HEADER_REGEX,
        value: '/sqlmap|nikto|nmap|masscan|burp|dirbuster/i',
        target: 'User-Agent'
    ),
    new PatternEntry(
        kind: PatternKind::HEADER_EXACT,
        value: '',
        target: 'User-Agent'
    ),
]);
$config->blocklistFromBackend('block-scanners', 'scanners');
```

### Block Sensitive Paths

```php
$backend = $config->inMemoryPatternBackend('paths', [
    new PatternEntry(PatternKind::PATH_EXACT, '/.env'),
    new PatternEntry(PatternKind::PATH_EXACT, '/.htpasswd'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/.git/'),
    new PatternEntry(PatternKind::PATH_PREFIX, '/wp-admin'),
    new PatternEntry(PatternKind::PATH_REGEX, '/\.(sql|bak|old)$/i'),
]);
$config->blocklistFromBackend('block-paths', 'paths');
```

### Temporary Blocks with Expiration

```php
$backend = $config->filePatternBackend('temp-blocks', '/var/lib/phirewall/temp.txt');

// Block for 1 hour
$backend->append(new PatternEntry(
    kind: PatternKind::IP,
    value: '203.0.113.100',
    expiresAt: time() + 3600,
    metadata: ['reason' => 'Rate limit abuse'],
));

// Block for 24 hours
$backend->append(new PatternEntry(
    kind: PatternKind::CIDR,
    value: '198.51.100.0/24',
    expiresAt: time() + 86400,
    metadata: ['reason' => 'DDoS source'],
));

// Clean up expired entries periodically
$backend->pruneExpired();
```

### Load from External Source

```php
// Load IPs from a threat intelligence feed
$threatIps = file('https://example.com/threat-ips.txt', FILE_IGNORE_NEW_LINES);
$entries = array_map(
    fn($ip) => new PatternEntry(PatternKind::IP, trim($ip)),
    array_filter($threatIps)
);

$backend = $config->inMemoryPatternBackend('threat-intel', $entries);
$config->blocklistFromBackend('threat-blocklist', 'threat-intel');
```

---

## Backend Methods

### append(PatternEntry $entry): void

Add or update a pattern entry.

```php
$backend->append(new PatternEntry(PatternKind::IP, '1.2.3.4'));
```

- Duplicate entries (same kind + value + target) are merged
- Expiration is extended to the later of existing/new

### consume(): PatternSnapshot

Get a point-in-time snapshot of all entries.

```php
$snapshot = $backend->consume();
foreach ($snapshot->entries as $entry) {
    echo "{$entry->kind}: {$entry->value}\n";
}
```

### pruneExpired(): void

Remove expired entries from storage.

```php
// Run periodically (e.g., via cron)
$backend->pruneExpired();
```

### type(): string

Returns the backend type (`'memory'` or `'file'`).

### capabilities(): array

Returns backend capabilities (supported kinds, max entries).

---

## Comparison: Pattern Backend vs Simple Blocklist

| Feature | `blocklist()` (closure) | Pattern Backend |
|---------|------------------------|-----------------|
| Storage | None (code only) | File or memory |
| Dynamic entries | No | Yes |
| Expiration | No | Yes |
| External updates | No | Yes (file) |
| Pattern types | Any (custom code) | Predefined kinds |
| Use case | Simple rules | Dynamic blocklists |

**Use `blocklist()` when:**
- Rules are simple and static
- Custom matching logic is needed

**Use Pattern Backend when:**
- Entries change at runtime
- Need expiration support
- External tools update the list
- Using standard pattern types (IP, CIDR, etc.)

---

## Best Practices

1. **Choose the right backend:**
   - `InMemoryPatternBackend` for static, configuration-based lists
   - `FilePatternBackend` for dynamic, persistent lists

2. **Use appropriate pattern kinds:**
   - Prefer `CIDR` over multiple `IP` entries for ranges
   - Use `PATH_PREFIX` instead of `PATH_REGEX` when possible (faster)

3. **Set expiration for temporary blocks:**
   - Always set `expiresAt` for automated blocks
   - Run `pruneExpired()` periodically to clean up

4. **Add metadata for diagnostics:**
   - Include `reason`, `source`, or `timestamp` in metadata
   - Helps with debugging and auditing

5. **Limit entry count:**
   - Backends enforce a maximum (default 10,000)
   - Large lists impact performance

---

## See Also

- [Configuration Reference](configuration.md) - API documentation
- [Example 07: IP Blocklist](../examples/07-ip-blocklist.php) - File-backed blocklist
- [Example 15: In-Memory Pattern Backend](../examples/15-in-memory-pattern-backend.php) - Configuration-based blocklist
