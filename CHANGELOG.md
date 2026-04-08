# Changelog

All notable changes to Phirewall are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-08

### Added

- **Config section API** — New `$config->safelists`, `$config->blocklists`, `$config->throttles`, `$config->fail2ban`, `$config->tracks` section objects replace flat `add*()` methods. Old methods are retained but deprecated for removal in 0.4. (#1)
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

- `DeprecatedConfigMethods` trait — all `add*()` / `get*()` methods on `Config`. Use the section API instead (`$config->safelists->add()`, `$config->blocklists->owasp()`, etc.). Will be removed in 0.4.

## [0.2.0] - 2026-01-27

Initial public release with core firewall functionality.

## [0.1.1] - 2025-12-14

Bugfixes and stability improvements.

## [0.1.0] - 2025-12-12

Initial development release.
