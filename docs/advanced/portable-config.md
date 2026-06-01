# Portable Config

> **Staged in-repo for the docs site.** This is the full page content; it is
> kept here until it can be published at `phirewall.de/advanced/portable-config`.
> Keep it in sync with the README "Portable Config" section and
> `examples/29-portable-config.php`.

`PortableConfig` expresses a firewall ruleset as plain, JSON-serializable data
instead of PHP closures. Because a ruleset is just data, you can:

- **store it in a database** and reload it on change (hot-reload),
- **ship it through a config service** (etcd, Consul, S3, a settings table),
- **diff and review it in git**, or
- **share one ruleset across many apps / processes / languages**

…and then rebuild a live [`Config`](https://phirewall.de) from it with
`toConfig()`. Closures are never serialized, so the surface is intentionally a
safe, declarative subset (see [Not portable by design](#not-portable-by-design)).

## Building and round-tripping

Build a ruleset fluently, export it with `toArray()` (or `json_encode()` the
result), and rebuild it with `fromArray()` → `toConfig()`:

```php
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;

$portable = PortableConfig::create()
    ->setKeyPrefix('shop')
    ->enableRateLimitHeaders()
    ->enableResponseHeaders()
    ->safelist('health', PortableConfig::filterPathEquals('/health'))
    ->blocklist('admin-probe', PortableConfig::filterPathPrefix('/wp-admin'))
    ->blocklist('scanners', PortableConfig::filterKnownScanners())
    ->blocklist('bad-net', PortableConfig::filterIp(['203.0.113.0/24']))
    ->throttle('api', limit: 100, period: 60, key: PortableConfig::keyHashedHeader('X-Api-Key'), sliding: true)
    ->allow2ban('volume-cap', threshold: 1000, period: 60, ban: 300, key: PortableConfig::keyIp())
    ->fail2ban('login', threshold: 5, period: 60, ban: 900, filter: PortableConfig::filterHeaderEquals('X-Login-Failed', '1'), key: PortableConfig::keyIp())
    ->patternBlocklist('threats', [
        PortableConfig::patternEntry(PatternKind::CIDR, '10.66.0.0/16'),
        PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.git(/|$)#'),
    ]);

// Export as data …
$json = json_encode($portable->toArray(), JSON_THROW_ON_ERROR);

// … and rebuild a live Config somewhere else.
$config   = PortableConfig::fromArray(json_decode($json, true, 512, JSON_THROW_ON_ERROR))->toConfig($cache);
$firewall = new Firewall($config);
```

`fromArray()` validates the *shape* of the data (rule/filter/key types, regex
patterns compile, pattern-entry fields) and throws `InvalidArgumentException`
on anything malformed. It does **not** verify *authenticity* — for that, see
[Signed transport](#signed-transport).

## The catalogue

Everything `PortableConfig` can express today.

### Rules

| Builder | Notes |
|---------|-------|
| `safelist(name, filter)` | Bypass all checks when the filter matches |
| `blocklist(name, filter)` | Deny (403) when the filter matches |
| `throttle(name, limit, period, key, sliding = false)` | Fixed or sliding-window rate limit (429) |
| `fail2ban(name, threshold, period, ban, filter, key)` | Auto-ban after repeated matching ("bad") requests |
| `allow2ban(name, threshold, period, ban, key)` | Hard volume cap — ban after too many *total* requests for a key |
| `track(name, period, filter, key, limit = null)` | Passive counting with optional alert threshold |
| `addPatternBackend(name, entries)` | Register a reusable catalogue of block patterns |
| `blocklistFromBackend(name, backendName)` | Add a blocklist that matches against a registered backend |
| `patternBlocklist(name, entries)` | Convenience: register a backend and a blocklist under one name |

### Filters (request predicates)

| Factory | Matches when … |
|---------|----------------|
| `filterAll()` | always |
| `filterPathEquals(path)` | the path equals `path` |
| `filterPathPrefix(prefix)` | the path starts with `prefix` |
| `filterPathRegex(pattern)` | the path matches the PCRE `pattern` (delimiters included) |
| `filterMethodEquals(method)` | the HTTP method equals `method` (case-insensitive) |
| `filterMethodIn(methods)` | the HTTP method is one of `methods` |
| `filterHeaderEquals(name, value)` | header `name` equals `value` |
| `filterHeaderPresent(name)` | header `name` is present with any non-empty value |
| `filterHeaderRegex(name, pattern)` | header `name` matches the PCRE `pattern` |
| `filterIp(ipsOrCidrs)` | the client IP is in the list (CIDR-aware, IPv4/IPv6) — backed by `IpMatcher` |
| `filterKnownScanners(patterns = null)` | the User-Agent matches a known scanner; `null` uses the curated default list — backed by `KnownScannerMatcher` |
| `filterSuspiciousHeaders(headers = null)` | a required browser header is missing; `null` uses the default set — backed by `SuspiciousHeadersMatcher` |

`filterIp`, `filterKnownScanners`, and `filterSuspiciousHeaders` compile to the
dedicated matcher classes (so you get their diagnostics and CIDR handling); the
remaining filters compile to a request-predicate closure.

### Key extractors

| Factory | Keys on |
|---------|---------|
| `keyIp()` | client IP (`REMOTE_ADDR`) |
| `keyMethod()` | HTTP method |
| `keyPath()` | request path |
| `keyHeader(name)` | raw value of header `name` |
| `keyHashedHeader(name)` | sha256 fingerprint of header `name` — preferred for credential-bearing headers (`Authorization`, `Cookie`, `X-Api-Key`) so the raw value never reaches the cache/ban registry |

### Pattern kinds (`PortableConfig::patternEntry()`)

Pattern backends carry a list of entries; each entry has a `PatternKind`:

| Kind | Matches |
|------|---------|
| `PatternKind::IP` | exact client IP |
| `PatternKind::CIDR` | client IP within a CIDR range |
| `PatternKind::PATH_EXACT` | exact path |
| `PatternKind::PATH_PREFIX` | path prefix |
| `PatternKind::PATH_REGEX` | path PCRE pattern |
| `PatternKind::HEADER_EXACT` | named header equals value (entry `target` = header name) |
| `PatternKind::HEADER_REGEX` | named header matches PCRE pattern (entry `target` = header name) |
| `PatternKind::REQUEST_REGEX` | pattern over path + query + headers |

`patternEntry()` also accepts optional `target`, `expiresAt`, `addedAt`, and a
scalar `metadata` map — all of which round-trip as data, so an entry can carry
its own expiry and provenance (handy when the catalogue lives in a database).

### Options

| Builder | Effect on the built `Config` |
|---------|------------------------------|
| `enableRateLimitHeaders()` | emit `X-RateLimit-*` headers |
| `enableResponseHeaders()` | emit `X-Phirewall-*` headers |
| `enableOwaspDiagnosticsHeader()` | emit the OWASP diagnostics header |
| `setFailOpen(bool)` | fail-open (default) vs fail-closed on backend errors |
| `setKeyPrefix(prefix)` | cache-key prefix |

## Pattern backends: rules in a database, hot-reloaded

Pattern backends are the natural fit for a block catalogue you maintain
*outside* code — e.g. a `blocked_patterns` table or a threat feed. Store the
serialized (ideally [signed](#signed-transport)) ruleset keyed by a version,
keep the compiled `Firewall` in memory, and rebuild only when the version
changes:

```php
// $store->load() returns ['version' => int, 'blob' => string] from your DB.
$loadedVersion = null;
$firewall = null;

function reload(Store $store, ?int &$loadedVersion, ?Firewall &$firewall, string $secret, Cache $cache): bool
{
    $row = $store->load();
    if ($loadedVersion === $row['version']) {
        return false; // already current — no rebuild
    }

    $portable = PortableConfig::loadSigned($row['blob'], $secret);
    $firewall = new Firewall($portable->toConfig($cache));
    $loadedVersion = $row['version'];

    return true;
}
```

When an operator publishes a new ruleset (and bumps the version), the next
`reload()` rebuilds the firewall; otherwise it is a no-op. See
[`examples/29-portable-config.php`](../../examples/29-portable-config.php) for a
runnable version with the database simulated in memory.

## Signed transport

When the serialized config is read back from storage you do **not** fully
control — a shared filesystem, an S3 bucket, etcd, a config service, a git repo
that accepts external contributions — an attacker who can write the blob could
inject an allow-all safelist and disable the firewall. `fromArray()` validates
shape only, not authenticity.

`toSignedJson()` / `loadSigned()` close that gap with an HMAC-SHA256 envelope:

```php
$signed   = $portable->toSignedJson($secretKey);             // <header>.<payload>.<signature>
$restored = PortableConfig::loadSigned($signed, $secretKey); // verifies before returning
```

- The envelope is JWS-compact-style: `<header>.<payload>.<signature>`, where the
  signature is HMAC-SHA256 over `<header>.<payload>`.
- Verification uses a constant-time `hash_equals()` compare. Any tampering —
  payload edit, key substitution, or an `alg=none` downgrade attempt — is
  rejected with a `RuntimeException` *before* the rules are applied.
- Signing keys must be at least 16 bytes; **32 random bytes is recommended**
  (`random_bytes(32)`), stored in your secrets manager.

See [`examples/28-portable-config-signing.php`](../../examples/28-portable-config-signing.php)
for a signing + tamper-rejection walkthrough.

## Not portable by design

A few capabilities cannot be represented as pure data and are intentionally
**excluded** from the schema. Configure these directly on the `Config` returned
by `toConfig()`:

| Excluded | Why |
|----------|-----|
| Trusted-bot reverse-DNS safelisting (`TrustedBotMatcher`) | needs live DNS resolution and an optional cache at request time |
| OWASP Core Rule Set (`blocklists->owasp()`) | a ruleset is parsed `SecRule` objects / rule files, not a small data blob |
| File-backed lists (`fileIp`, `filePatternBackend`) | filesystem paths are environment-specific; the in-memory pattern backend is the portable equivalent |
| Closure-driven dynamic throttle limits/periods, `multiThrottle` | limits/periods can be arbitrary PHP closures and cannot be serialized (express the multi-window case as several `throttle()` entries; `sliding` is supported) |
| Response factories, `ipResolver`, `discriminatorNormalizer` | these are closures / objects, not declarative data |

## Examples

- [`examples/28-portable-config-signing.php`](../../examples/28-portable-config-signing.php) — signed transport and tamper rejection.
- [`examples/29-portable-config.php`](../../examples/29-portable-config.php) — round-trip, signing, and a database hot-reload scenario.
