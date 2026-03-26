# TODO – Phirewall Development Plan

## Merged to main (0.3.0)

- [x] Config section objects refactor with PSR-14 diagnostics (#1)
- [x] Comprehensive tests: InMemoryPatternBackend, benchmarks, edge cases, value objects (#2)
- [x] Fix broken REQUEST_REGEX matching and O(n²) pruning (#3)
- [x] KnownScannerMatcher and blocklists->knownScanners() (#5)
- [x] TrustedBotMatcher, SuspiciousHeadersMatcher, IpMatcher, shared matcher utilities (#6)
- [x] Allow2Ban rule type with BanManager API, validation, security hardening (#7)
- [x] Sliding window throttle with strategy pattern (#8)
- [x] multiThrottle, dynamic throttle limits, disable toggle, discriminator normalizer (#9)
- [x] Track threshold with optional limit and thresholdReached flag (#10)
- [x] PdoCache storage backend, reset helpers, database test infrastructure (#11)
- [x] Fail-open/fail-closed middleware error handling (#12)
- [x] Comprehensive infrastructure adapter tests with vfsStream (#13)
- [x] PSR-17 response factory support (#14)

## Pending (ready to push)

- [*] `feature/docs-update` — Documentation migrated to section API with FQN, Symfony example, all deprecated references removed
- [*] `feature/changelog` — CHANGELOG.md for 0.3.0
- [*] `feature/publish-workflow` — GitHub Actions release workflow (publish.yml)

## Future ideas

### Architecture (from full review)
- [ ] Extract `Firewall::decide()` into dedicated evaluator classes per rule type (SRP)
- [x] Extract shared fail2ban check/increment/ban/dispatch logic into a private method used by both `decide()` and `processRecordedFailure()`
- [ ] Remove duplicated increment logic between `Firewall::increment()` and `FixedWindowStrategy`
- [x] Extract `CoreRule::evaluateOperator()` and `collectVariableValues()` into strategy classes
- [x] Response-based fail2ban counting via RequestContext (inspect response after handler)
- [ ] Remove `DeprecatedConfigMethods` trait in next major version
- [ ] `PortableConfig::toConfig()` uses deprecated methods — migrate to section API
- [x] `DiagnosticsCounters` implements `EventDispatcherInterface` — semantic mismatch, should wrap a real dispatcher

### Features
- [ ] Exponential backoff throttle strategy
- [ ] GeoIP-based blocking (requires external dependency)
- [ ] Request body inspection for POST data analysis
- [ ] Path normalization (remove trailing slashes, double slashes)
- [ ] Add Presets for common use cases (API rate limiting, login protection, etc) with recommended rules and configuration with update check for new versions

### Performance (from full review)
- [ ] SHA-256 per-request memoization in CacheKeyGenerator for repeated keys in single decide()
- [ ] SlidingWindowStrategy 3 cache operations → pipeline or dedicated CounterStoreInterface method
- [ ] Shared OWASP variable extraction cache across rules (collectVariableValues called N times)
- [ ] InMemoryCache: purge only on set/increment, not get; consider time-based vs count-based
- [ ] BanManager::registerBan() full JSON read-modify-write per ban — consider Redis HASH or key-per-ban

### Security (from full review)
- [x] Make X-Phirewall/X-Phirewall-Matched response headers opt-in (disabled by default) — breaking change
- [ ] Ban registry size cap to prevent DoS under mass-ban scenarios
- [ ] ReDoS length guard on CoreRule @rx (route through RegexMatcher or add strlen check)
- [ ] Document fail2ban non-atomic counter as backend-dependent security limitation
- [ ] Sliding window non-atomic read-modify-write — document limitation or provide atomic path
- [ ] RedisCache::increment() fails silently returning 0 — add logging or event dispatch

### Internal improvements
- [ ] Inject ClockInterface into BanManager for consistent time handling
- [ ] Add TTL to ban registry cache entries based on max(expiresAt)
- [ ] DiagnosticsCounters should track Allow2Ban events
- [ ] Consistent validation across all rule types (Fail2BanRule has none)
- [ ] `PatternKind` → string-backed enum
- [ ] Extract duplicated `mergeEntry()` and `entryKey()` from pattern backends

### PSR-16 compliance (all cache backends)
- [ ] Add key validation (`Psr\SimpleCache\InvalidArgumentException` for invalid keys)
- [ ] `getMultiple()`/`deleteMultiple()` should throw for non-string keys instead of casting

### PdoCache improvements
- [ ] Make pruning probability configurable via constructor parameter
- [ ] `setMultiple()` transaction wrapping for efficiency
- [ ] Replace `\w` with `[a-zA-Z0-9_]` in table name regex for locale safety
- [ ] Document WAL mode more prominently for SQLite with concurrent PHP-FPM workers

### Framework integrations
- [ ] TYPO3 extension package (`flowd/phirewall-typo3`) — PSR-15 native, highest priority
- [ ] Symfony bundle (`flowd/phirewall-symfony-bundle`) — auto-config, services.yaml, DI wiring
- [ ] Laravel native middleware example using `Firewall::decide()` directly (no PSR-15 bridge)
- [ ] Shopware plugin guidance — multi-storefront, API vs storefront rate limits
- [ ] Document multi-context patterns (per API group, per tenant, per sales channel)

## Stale branches (can be deleted)

All feature branches below have been merged or superseded. Safe to delete:

`feature/matcher-refactor`, `feature/config-refactor`, `feature/config-sections`,
`feature/bugfixes`, `feature/bugfixes-v2`, `feature/test-coverage`, `feature/test-coverage-v2`,
`feature/known-scanner-blocklist`, `feature/matchers`, `feature/perf-tests`,
`feature/test-improvements`, `feature/pdo-storage`, `feature/reset-help`,
`feature/disc-normalizer`, `feature/disable-toggle`, `feature/dynamic-throttle`,
`feature/multi-throttle`, `feature/throttle-features`, `feature/throttle-features-v2`,
`feature/sliding-window`, `feature/sliding-window-v2`, `feature/sliding-window-v3`,
`feature/allow2ban`, `feature/allow2ban-v2`, `feature/track-threshold`,
`feature/track-threshold-v2`, `feature/track-limit`, `feature/trusted-bot`,
`feature/trusted-bot-matcher`, `feature/header-analysis`, `feature/ip-helpers`,
`feature/fix-request--matching`, `feature/discriminator-normalizer`,
`feature/reset-helpers`, `feature/storage-helpers`, `feature/htaccess-tests`,
`feature/psr17-factories`, `feature/fail-open-middleware`

Separate repo: `feature/docs-site`, `feature/docs-features`, `feature/docs-advanced`
