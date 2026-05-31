# Changelog

All notable changes to Phirewall are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased — 0.5.0

### Added

- **`KeyExtractors::hashedHeader(string $name)`** — Returns a key extractor that yields the sha256 fingerprint of the named header value instead of the raw value. Preferred over `KeyExtractors::header()` whenever the header is credential-bearing (`Authorization`, `Cookie`, `X-Api-Key`, …), so the cache backend and the ban registry store the fingerprint rather than the verbatim value. The hash is unkeyed sha256 — a deterministic bucket identifier, not a credential-hardening primitive: low-entropy values remain grindable from a leaked cache dump, and the fingerprint does not defeat a chosen-key probing attacker. The `header()` docblock now points readers at this helper.
- **`RequestContext::recordHit()`** — Counterpart of `recordFailure()` for allow2ban rules. Handlers can now signal handler-observable hits (e.g. an expensive operation completed, a webhook delivered a duplicate payload) and have them counted against an allow2ban threshold post-handler, mirroring the fail2ban-via-RequestContext pattern.

### Changed

- **BREAKING — `TrustedProxyResolver` default `$allowedHeaders` is now `['X-Forwarded-For']`** — Previously the default was `['X-Forwarded-For', 'Forwarded']` and the resolver returned on the first non-empty header in declared order. Operators on stacks that emit RFC 7239 `Forwarded` should pass `['Forwarded']` (or both names) explicitly so the chosen header is visible in the call site rather than inferred from a default. Migration: integrators that relied on the implicit `Forwarded` fallback need to opt in by passing the value at the construction site.
- **BREAKING — `RequestContext::recordFailure()` second parameter is now optional and the recorded type renamed** — When `$key` is omitted, the firewall extracts the discriminator from the matching rule's `keyExtractor` against the current request, so handlers no longer need to know whether the rule keys on IP, header, or anything else. `RecordedFailure` was renamed to `RecordedSignal` and gained a `BanType $banType` field so the same recorder can route fail2ban and allow2ban signals through the same channel. `RequestContext::getRecordedFailures()` is replaced by `getRecordedSignals()`; integrators iterating recorded signals manually (rare — `Middleware::process()` does this internally) need to update the method name and adapt to the new field on the returned objects. The existing explicit-key form (`recordFailure($name, $key)`) continues to work unchanged.

- **`BanManager` registry has a TTL and prunes expired entries on save** — Previously the per-rule ban registry (the audit-view list backing `listBans()` / `listRulesWithBans()`) was written without a TTL and grew monotonically across ban churn. Each save now applies a TTL equal to the longest-surviving entry's remaining lifetime, and `saveRegistry()` prunes already-expired entries before writing so the registry tracks live bans only. The registry is best-effort under concurrent `ban()` calls for the same rule (the primary ban cache key set by `ban()` is the source of truth and is not affected).
- **`RedisCache::increment()` re-throws on Redis errors instead of returning `0`** — Previously any `\Throwable` from the underlying Predis client (connection refused, AUTH failure, Lua script error, network blip) was swallowed and `increment()` returned `0`, which every throttle / fail2ban / allow2ban rule then interpreted as "no hits this window". The method now re-throws the original `\Throwable` after emitting an `E_USER_WARNING` for diagnostic visibility, so `Middleware::process()` applies the configured `Config::failOpen` policy uniformly for Redis errors. Integrators relying on the prior fail-open behaviour can keep `Config::failOpen` at its current default of `true`; those wanting the failure to surface as a 5xx can set it to `false`.
- **Observability examples extract a curated subset instead of dumping the event** — `examples/09-observability-monolog.php` previously called `get_object_vars($event)` and passed the result to Monolog, which serialised the embedded `ServerRequest` (every header + parsed body) into the log sink. The example now uses an explicit `summarize()` helper that extracts only the rule name, method, path, remote address, and a short sha256-prefix fingerprint of the discriminator key. `examples/10-observability-opentelemetry.php` switched from `phirewall.key` to `phirewall.key_fingerprint` for the same reason.
- **`TrustedProxyResolver` keeps the rightmost `maxChainEntries` of an oversized chain, not the leftmost** — When `X-Forwarded-For` (or `Forwarded`) carried more entries than `maxChainEntries` (default 50), the parser truncated from the left and returned early, dropping the entries closest to the receiver. Because those rightmost entries are the ones added by proxies along the request path, the truncation could discard the authoritative tail in favour of arbitrary leading content. The parser now slices to the last N entries before walking the chain right-to-left.
- **`@pmFromFile` confines resolved paths to the configured context folder** — When `PhraseMatchFromFileEvaluator` is constructed with a `$contextFolder`, the operand is now rejected if it is an absolute path, and the resolved path (via `realpath()`) is verified to remain under `realpath($contextFolder)`. Catches symlinks pointing outside the rules directory in addition to the existing `..` traversal check. `SecRuleLoader::fromFile()` now derives the loaded file's own directory as the context folder (mirroring `fromFiles()`/`fromDirectory()`), so single-file loads are confined too. When `$contextFolder` is `null` (only `SecRuleLoader::fromString()` and direct in-process construction), the prior behaviour is unchanged.
- **`ApacheHtaccessAdapter` serialises concurrent writers via `flock()`** — `blockMany()` / `unblockMany()` now acquire an exclusive advisory lock on a sidecar `${htaccessPath}.lock` file for the read-modify-write cycle that culminates in the atomic rename. Two processes invoking `blockIp()` simultaneously will now serialize on the lock instead of clobbering each other's update. The lock file is created on first use and never renamed, so it remains a stable lock target across writes.
- **`FilePatternBackend` and `FileIpBlocklistStore` write via temp file + atomic rename, serialized by a sidecar lock** — Both stores previously wrote the new contents by `ftruncate(0) + fwrite` on the live file handle. A PHP fatal between the truncate and the fwrite would leave the file empty (every entry the operator had recorded silently lost). The full-rewrite path now writes to `${filePath}.tmp.<random>` and `rename()`s onto the target so the live file is either the old content or the new content, never an empty in-between state. Writers now serialize on a dedicated, never-renamed `${filePath}.lock` sidecar file rather than on the live file: because `rename()` swaps the live file's inode, a lock held on the live file would be stranded on the orphaned inode and a second writer already blocked on it would resume against stale content and clobber the just-completed update. The temp file is also `chmod()`ed to match the live file's mode (owner-only `0600` when it does not yet exist) so the rename never widens a restrictive permission set. `FileIpBlocklistStore`'s append-only path is unchanged because a trailing partial line is tolerated by the parser and reconciled on the next rewrite.
- **Pattern and blocklist auto-created directories use mode `0700` instead of `0777`** — `FilePatternBackend::ensureDirectory()` and `FileIpBlocklistStore::ensureDirectory()` previously created missing parent directories world-readable / writable. The default is now `0700` so the contents are restricted to the owning user on shared hosts. Operators who need a wider mode can pre-create the directory with the permissions they want (auto-create only fires when the path does not yet exist).
- **`FileIpBlocklistMatcher` and `InfrastructureBanListener` docblocks call out the REMOTE_ADDR default** — Both constructors fall back to `KeyExtractors::ip()` when no `$ipResolver` / `$requestToIp` is supplied. That extractor reads `REMOTE_ADDR` verbatim, which behind a CDN or load balancer is the proxy's address rather than the client's. The constructor docblocks now point integrators at `KeyExtractors::clientIp(new TrustedProxyResolver([...]))` for the proxy case so the blocklist match (and any infrastructure ban that follows) targets the originating client.

### Fixed

- **`TrustedProxyResolver` resolves bracketed IPv6+port forms in `X-Forwarded-For` and `Forwarded`** — Entries like `[2001:db8::1]:443` (the form RFC 7239 mandates for IPv6 in `Forwarded for=`, and one some proxies emit in XFF) were silently dropped: bracket-stripping left `2001:db8::1]:443`, which failed `FILTER_VALIDATE_IP`, and the resolver fell back to `REMOTE_ADDR`. `normalizeIp()` now extracts the address from `[…](:port)?` before validating, and the `Forwarded for=` regex no longer over-captures the trailing `]`.

## 0.4.0 - 2026-05-19

### Changed

- **BREAKING CHANGE — Ban evaluator threshold semantics unified to `>=`** — `Fail2BanEvaluator` (pre-handler path) and `Allow2BanEvaluator` previously banned only after the threshold was **exceeded**: on the **(N+1)th** matching request when `threshold = N` (they used `$count > $threshold`). They now ban as soon as the threshold is **reached**: on the **Nth** matching request (using `$count >= $threshold`), matching the post-handler fail2ban path, the diagnostics events, and classic fail2ban semantics where `maxretry = N` means "ban at the Nth attempt".

  `ThrottleEvaluator` is **not** affected: throttle still uses `$count > $limit` because "N requests per period, 429 on the (N+1)th" is the standard HTTP rate-limit contract.

  **Migration:** if you relied on the old behavior (e.g. `threshold: 5` to mean "ban on the 6th request"), subtract 1 from your `threshold` values to retain it.

  The internal `Fail2BanEvaluator::incrementAndBanIfNeeded()` method also drops its `bool $postHandler` parameter — the two paths now share the same "ban when the threshold is reached" semantic. Callers outside `Firewall` that passed this argument must remove it.

### Fixed

- **`RegexEvaluator` no longer treats literal first/last characters of `@rx` patterns as PCRE delimiters** — The previous `ensureRegexDelimiters()` heuristic checked whether a pattern's first and last characters were the same non-alphanumeric, non-bracket character and, if so, returned it unchanged on the assumption that it was already `~…~`-style delimited. ModSecurity/CRS `@rx` patterns are bare regex content by spec, so this heuristic could misfire on rules whose patterns happen to start and end with the same literal character. The clearest case is **CRS 942510** ("SQLi bypass attempt by ticks or backticks"), whose pattern is wrapped in literal backticks; under the old code those backticks were consumed as PCRE delimiters and the rule collapsed to its inner alternation, which matched almost any HTTP value. The `@rx` operator now always wraps in `~…~u` and escapes unescaped `~`. **API change:** the public static `RegexEvaluator::ensureRegexDelimiters()` has been removed; use `RegexEvaluator::wrapInTildeDelimiters()` if you need the helper directly.
- **`SecRuleParser` no longer strips literal quote characters from `@rx` arguments** — The parser previously ran `stripQuotes()` on every operator argument, which corrupted `@rx` patterns whose first and last bytes were matching `'` or `"`. The clearest case is **CRS 942511** (a variant of 942510), whose alternation is wrapped in literal apostrophes; the parser ate those apostrophes before the pattern reached `RegexEvaluator`, collapsing the rule to its inner body and matching essentially every HTTP value. `@rx` arguments are bare PCRE per ModSecurity grammar — the outer SecRule-level quoting is removed once at the line level and there is no second quoting layer to strip. The 942510 fix only addressed the evaluator-side delimiter heuristic; this completes the fix on the parser side. Non-`@rx` operators retain the existing `stripQuotes` + `unescape` behavior.

## 0.3.0 - 2026-04-08

### Added

- **Config section API** — New `$config->safelists`, `$config->blocklists`, `$config->throttles`, `$config->fail2ban`, `$config->tracks` section objects replace flat `add*()` methods. Old methods are retained but deprecated for removal in 0.5. (#1)
- **PSR-14 diagnostics** — `DiagnosticsCounters` observer with `DiagnosticsDispatcher` wrapper for event counting and forwarding. Tracks safelisted, blocklisted, throttled, fail2ban, allow2ban, and track events. (#1, #30, #33)
- **KnownScannerMatcher** — Block sqlmap, nikto, nmap, burp, and other scanner User-Agents via `$config->blocklists->knownScanners()`. (#5)
- **TrustedBotMatcher** — Safelist Googlebot, Bingbot, etc. via reverse DNS verification. (#6)
- **SuspiciousHeadersMatcher** — Block requests missing standard browser headers. (#6)
- **IpMatcher** — Safelist or block by IP/CIDR range with shared matcher utilities. (#6)
- **Allow2Ban** — Hard volume cap with auto-ban after threshold. Includes BanManager API, validation, and security hardening. (#7)
- **Sliding window throttle** — `SlidingWindowStrategy` for smoother rate limiting alongside existing fixed-window strategy. (#8)
- **Multi-window throttle** — `$config->throttles->multi()` for burst + sustained rate limiting with multiple windows. (#9)
- **Dynamic throttle limits** — Closure-based limits that can vary per request (e.g., by user role). (#9)
- **Throttle disable toggle** — Disable individual throttle rules without removing configuration. (#9)
- **Discriminator normalizer** — Normalize throttle/fail2ban keys (e.g., lowercase, trim) via callable. (#9)
- **Track with threshold** — `$config->tracks->add()` now supports optional `limit` parameter with `thresholdReached` flag for passive counting with alerting. (#10)
- **PdoCache** — SQL-backed PSR-16 cache for MySQL, PostgreSQL, and SQLite with probabilistic pruning and WAL mode support. (#11)
- **Fail-open/fail-closed** — Configurable middleware error handling: fail-open (default) continues on cache errors, fail-closed returns 503. Errors dispatched via PSR-14. (#12)
- **PSR-17 response factories** — `$config->usePsr17Responses()` and dedicated `Psr17BlocklistedResponseFactory` / `Psr17ThrottledResponseFactory` for framework-native responses. (#14)
- **RequestContext** — Post-handler fail2ban signaling via request attributes. Record failures from your login handler without pre-filtering. (#22)
- **DecisionPath enum** — Type-safe representation of all firewall decision outcomes. (#16)
- **Evaluator classes** — Dedicated per-rule-type evaluator classes (`SafelistEvaluator`, `BlocklistEvaluator`, `ThrottleEvaluator`, `Fail2BanEvaluator`, `Allow2BanEvaluator`, `TrackEvaluator`) extracted from `Firewall::decide()` for SRP. (#31)
- **PatternKind enum** — `PatternKind` converted from class with string constants to a string-backed enum. `PatternEntry` gains `key()` and `merge()` methods, deduplicating logic from pattern backends. (#32)
- **ReDoS length guard** — `RegexEvaluator` skips values exceeding 8 KiB before running regex, preventing catastrophic backtracking on crafted payloads. Reuses `RegexMatcher::MAX_SUBJECT_LENGTH`. (#34)

### Changed

- **Response headers are opt-in** — `X-Phirewall`, `X-Phirewall-Matched`, and `X-Phirewall-Safelist` headers are no longer added by default. Call `$config->enableResponseHeaders()` to enable them. `Retry-After` remains always-on for throttled responses. **Breaking change.** (#25)
- **Fail2Ban/Allow2Ban threshold semantics** — Ban now triggers after N failures (threshold reached), not on the Nth failure attempt. This is a correctness fix but changes observable behavior for edge cases. (#26)
- **RedisCache::increment()** — Now emits `E_USER_WARNING` via `trigger_error()` on Redis errors before returning 0 (fail-open preserved, including when error handlers throw). (#35)
- **Constructor validation** — All rule types (`ThrottleRule`, `Fail2BanRule`, `Allow2BanRule`, `TrackRule`, `SafelistRule`, `BlocklistRule`) now validate parameters on construction. (#18)
- **OWASP operator preprocessing** — `@rx`, `@pm`, `@pmFromFile` operators cache compiled patterns for reuse. (#20)
- **Discriminator normalizer** — Resolved once at top of `decide()` instead of per-rule. (#21)
- **Fixed-window counter** — Shared `FixedWindowCounter` eliminates duplicated increment logic. (#27)
- **Fail2Ban logic** — Shared increment-and-ban helper used by both pre-handler and post-handler (RequestContext) paths. (#29)
- **DiagnosticsCounters** — No longer implements `EventDispatcherInterface` directly. Use `DiagnosticsDispatcher` to both count and forward events. (#30)

### Fixed

- **REQUEST_REGEX matching** — Broken pattern matching and O(n^2) pruning in pattern backends. (#3)
- **Fail2Ban/Allow2Ban threshold off-by-one** — Threshold comparison now uses `>=` consistently. (#26)
- **@pmFromFile path traversal** — Prevented directory traversal via `@pmFromFile` operator argument. (#20)
- **PatternEntry merge** — Merging two permanent entries (null expiresAt) no longer produces expiresAt: 0. Permanent entries always win when merged. (#32)
- **Hardcoded credentials** — Replaced hardcoded database credentials with `getenv()` in PdoCache example. (#19)

### Security

- Response headers are now opt-in to prevent information leakage in production. (#25)
- `@pmFromFile` path traversal prevention. (#20)
- ReDoS length guard (8 KiB) on OWASP `@rx` operator. (#34)
- RedisCache failures are now visible via `E_USER_WARNING` instead of silently swallowed. (#35)

### Deprecated

- `DeprecatedConfigMethods` trait — all `add*()` / `get*()` methods on `Config`. Use the section API instead (`$config->safelists->add()`, `$config->blocklists->owasp()`, etc.). Will be removed in 0.5.

## [0.2.0] - 2026-01-27

Initial public release with core firewall functionality.

## [0.1.1] - 2025-12-14

Bugfixes and stability improvements.

## [0.1.0] - 2025-12-12

Initial development release.
