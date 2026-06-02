<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Portable;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\ThrottleRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use Flowd\Phirewall\Matchers\SuspiciousHeadersMatcher;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A portable representation of firewall rules that can be exported/imported as arrays (or JSON).
 *
 * Scope: Supports a constrained, safe subset of rule definitions using named extractors and simple filters.
 * This avoids serializing arbitrary closures while enabling sharing of common rule sets across apps/processes.
 */
/**
 * @phpstan-type FilterTypeGeneric array{type: string}
 * @phpstan-type FilterTypeAll array{type: 'all'}
 * @phpstan-type FilterTypeNone array{type: 'none'}
 * @phpstan-type FilterMethodEquals FilterTypeGeneric&array{type: 'method_equals', method: string}
 * @phpstan-type FilterMethodIn FilterTypeGeneric&array{type: 'method_in', methods: list<string>}
 * @phpstan-type FilterPathEquals FilterTypeGeneric&array{type: 'path_equals', path: string}
 * @phpstan-type FilterPathPrefix FilterTypeGeneric&array{type: 'path_prefix', prefix: string}
 * @phpstan-type FilterPathRegex FilterTypeGeneric&array{type: 'path_regex', pattern: string}
 * @phpstan-type FilterHeaderEquals FilterTypeGeneric&array{type: 'header_equals', name: string, value: string}
 * @phpstan-type FilterHeaderPresent FilterTypeGeneric&array{type: 'header_present', name: string}
 * @phpstan-type FilterHeaderRegex FilterTypeGeneric&array{type: 'header_regex', name: string, pattern: string}
 * @phpstan-type FilterIp FilterTypeGeneric&array{type: 'ip', ips: list<string>}
 * @phpstan-type FilterKnownScanners FilterTypeGeneric&array{type: 'known_scanners', patterns?: list<string>}
 * @phpstan-type FilterSuspiciousHeaders FilterTypeGeneric&array{type: 'suspicious_headers', headers?: list<string>}
 * @phpstan-type Filter FilterMethodEquals|FilterMethodIn|FilterPathEquals|FilterPathPrefix|FilterPathRegex|FilterHeaderEquals|FilterHeaderPresent|FilterHeaderRegex|FilterIp|FilterKnownScanners|FilterSuspiciousHeaders|FilterTypeGeneric|FilterTypeAll|FilterTypeNone
 * @phpstan-type Key array{type: 'ip'}|array{type: 'method'}|array{type: 'path'}|array{type: 'header', name: string}|array{type: 'hashed_header', name: string}
 * @phpstan-type PatternEntryArray array{kind: string, value: string, target?: string|null, expiresAt?: int|null, addedAt?: int|null, metadata?: array<string, scalar>}
 * @phpstan-type SchemaSafelists list<array{name: string, filter: Filter}>
 * @phpstan-type SchemaBlocklists list<array{name: string, filter: Filter}>
 * @phpstan-type SchemaThrottles list<array{name: string, limit: int, period: int, key: Key, sliding?: bool, scope?: Filter}>
 * @phpstan-type SchemaFail2Bans list<array{name: string, threshold: int, period: int, ban: int, filter: Filter, key: Key}>
 * @phpstan-type SchemaAllow2Bans list<array{name: string, threshold: int, period: int, ban: int, key: Key}>
 * @phpstan-type SchemaTracks list<array{name: string, period: int, filter: Filter, key: Key, limit?: int}>
 * @phpstan-type SchemaPatternBackends list<array{name: string, entries: list<PatternEntryArray>}>
 * @phpstan-type SchemaPatternBlocklists list<array{name: string, backend: string}>
 * @phpstan-type SchemaOptions array{rateLimitHeaders?: bool, responseHeaders?: bool, owaspDiagnosticsHeader?: bool, failOpen?: bool, keyPrefix?: string}
 * @phpstan-type Schema array{
 *   safelists: SchemaSafelists,
 *   blocklists: SchemaBlocklists,
 *   throttles: SchemaThrottles,
 *   fail2bans: SchemaFail2Bans,
 *   allow2bans: SchemaAllow2Bans,
 *   tracks: SchemaTracks,
 *   patternBackends: SchemaPatternBackends,
 *   patternBlocklists: SchemaPatternBlocklists,
 *   options: SchemaOptions
 * }
 */
final class PortableConfig
{
    /**
     * `typ` value used inside the signed envelope header. Bumping the version
     * suffix is the migration path when the wire format changes incompatibly.
     */
    private const SIGNED_TYPE = 'phirewall.config.v1';

    /**
     * Minimum HMAC key length accepted by {@see toSignedJson()} and
     * {@see loadSigned()}. 16 bytes (128 bits) is the floor for HMAC-SHA256
     * keys recommended by NIST SP 800-107; 32 bytes is preferred. The check
     * rejects the empty string and short test-fixture values that would
     * otherwise produce a usable but trivially-brute-forceable signature.
     */
    private const MIN_SECRET_KEY_LENGTH = 16;

    /** @var Schema */
    private array $schema = [
        'safelists' => [],
        'blocklists' => [],
        'throttles' => [],
        'fail2bans' => [],
        'allow2bans' => [],
        'tracks' => [],
        'patternBackends' => [],
        'patternBlocklists' => [],
        'options' => [],
    ];

    public static function create(): self
    {
        return new self();
    }

    public function enableRateLimitHeaders(bool $enabled = true): self
    {
        $this->schema['options']['rateLimitHeaders'] = $enabled;
        return $this;
    }

    public function enableResponseHeaders(bool $enabled = true): self
    {
        $this->schema['options']['responseHeaders'] = $enabled;
        return $this;
    }

    public function setKeyPrefix(string $prefix): self
    {
        $this->schema['options']['keyPrefix'] = $prefix;
        return $this;
    }

    public function enableOwaspDiagnosticsHeader(bool $enabled = true): self
    {
        $this->schema['options']['owaspDiagnosticsHeader'] = $enabled;
        return $this;
    }

    /**
     * Control the fail-open / fail-closed policy of the resulting Config.
     *
     * Mirrors {@see Config::setFailOpen()}; the default (true) is only emitted
     * into the schema when explicitly set so existing serialized configs keep
     * their shape.
     */
    public function setFailOpen(bool $failOpen): self
    {
        $this->schema['options']['failOpen'] = $failOpen;
        return $this;
    }

    /**
     * @return FilterPathEquals
     */
    public static function filterPathEquals(string $path): array
    {
        return ['type' => 'path_equals', 'path' => $path];
    }

    /**
     * @return FilterMethodEquals
     */
    public static function filterMethodEquals(string $method): array
    {
        return ['type' => 'method_equals', 'method' => strtoupper($method)];
    }

    /**
     * @return FilterHeaderEquals
     */
    public static function filterHeaderEquals(string $name, string $value): array
    {
        return ['type' => 'header_equals', 'name' => $name, 'value' => $value];
    }

    /**
     * @return FilterTypeAll
     */
    public static function filterAll(): array
    {
        return ['type' => 'all'];
    }

    /**
     * A filter that never matches any request.
     *
     * The portable counterpart of `fn() => false`. Use it for a fail2ban rule
     * that must not be tripped by any inspectable, client-controlled request
     * property (e.g. a spoofable marker header) and is instead driven solely by
     * a trusted post-handler signal via `RequestContext::recordFailure()`, which
     * bypasses the filter.
     *
     * @return FilterTypeNone
     */
    public static function filterNone(): array
    {
        return ['type' => 'none'];
    }

    /**
     * Match requests whose path starts with the given prefix.
     *
     * @return FilterPathPrefix
     */
    public static function filterPathPrefix(string $prefix): array
    {
        return ['type' => 'path_prefix', 'prefix' => $prefix];
    }

    /**
     * Match requests whose path matches the given PCRE pattern (delimiters included, e.g. `#^/admin#`).
     *
     * @return FilterPathRegex
     */
    public static function filterPathRegex(string $pattern): array
    {
        return ['type' => 'path_regex', 'pattern' => $pattern];
    }

    /**
     * Match requests whose method is one of the given methods (case-insensitive).
     *
     * @param list<string> $methods
     * @return FilterMethodIn
     */
    public static function filterMethodIn(array $methods): array
    {
        $methods = self::requireNonEmptyStringList($methods, 'filterMethodIn()');
        return ['type' => 'method_in', 'methods' => array_values(array_map(static fn(string $method): string => strtoupper($method), $methods))];
    }

    /**
     * Match requests that carry the given header (any non-empty value).
     *
     * @return FilterHeaderPresent
     */
    public static function filterHeaderPresent(string $name): array
    {
        return ['type' => 'header_present', 'name' => $name];
    }

    /**
     * Match requests whose named header value matches the given PCRE pattern.
     *
     * @return FilterHeaderRegex
     */
    public static function filterHeaderRegex(string $name, string $pattern): array
    {
        return ['type' => 'header_regex', 'name' => $name, 'pattern' => $pattern];
    }

    /**
     * Match requests whose client IP is in the given list of IPs and/or CIDR ranges.
     *
     * Backed by {@see IpMatcher}; resolves the client IP from REMOTE_ADDR.
     *
     * @param list<string> $ipsOrCidrs
     * @return FilterIp
     */
    public static function filterIp(array $ipsOrCidrs): array
    {
        return ['type' => 'ip', 'ips' => self::requireNonEmptyStringList($ipsOrCidrs, 'filterIp()')];
    }

    /**
     * Match requests whose User-Agent matches a known scanner / attack tool.
     *
     * Backed by {@see KnownScannerMatcher}. Pass null (default) to use the
     * curated default pattern list; pass an explicit list to override it.
     *
     * @param list<string>|null $patterns
     * @return FilterKnownScanners
     */
    public static function filterKnownScanners(?array $patterns = null): array
    {
        $filter = ['type' => 'known_scanners'];
        if ($patterns !== null) {
            $filter['patterns'] = self::requireNonEmptyStringList($patterns, 'filterKnownScanners()');
        }

        return $filter;
    }

    /**
     * Match requests missing standard browser headers.
     *
     * Backed by {@see SuspiciousHeadersMatcher}. Pass null (default) to require
     * the default header set; pass an explicit list to override it.
     *
     * @param list<string>|null $requiredHeaders
     * @return FilterSuspiciousHeaders
     */
    public static function filterSuspiciousHeaders(?array $requiredHeaders = null): array
    {
        $filter = ['type' => 'suspicious_headers'];
        if ($requiredHeaders !== null) {
            $filter['headers'] = self::requireNonEmptyStringList($requiredHeaders, 'filterSuspiciousHeaders()');
        }

        return $filter;
    }

    /**
     * @return array{type: 'ip'}
     */
    public static function keyIp(): array
    {
        return ['type' => 'ip'];
    }

    /**
     * @return array{type: 'method'}
     */
    public static function keyMethod(): array
    {
        return ['type' => 'method'];
    }

    /**
     * @return array{type: 'path'}
     */
    public static function keyPath(): array
    {
        return ['type' => 'path'];
    }

    /**
     * @return array{type: 'header', name: string}
     */
    public static function keyHeader(string $name): array
    {
        return ['type' => 'header', 'name' => $name];
    }

    /**
     * Key on a sha256 fingerprint of the named header rather than its raw value.
     *
     * Backed by {@see KeyExtractors::hashedHeader()}; preferred for
     * credential-bearing headers (`Authorization`, `Cookie`, `X-Api-Key`).
     *
     * @return array{type: 'hashed_header', name: string}
     */
    public static function keyHashedHeader(string $name): array
    {
        return ['type' => 'hashed_header', 'name' => $name];
    }

    /**
     * Build a single pattern-backend entry (a portable {@see PatternEntry}).
     *
     * @param array<string, scalar> $metadata
     * @return PatternEntryArray
     */
    public static function patternEntry(
        PatternKind $patternKind,
        string $value,
        ?string $target = null,
        ?int $expiresAt = null,
        ?int $addedAt = null,
        array $metadata = [],
    ): array {
        $entry = ['kind' => $patternKind->value, 'value' => $value];
        if ($target !== null) {
            $entry['target'] = $target;
        }

        if ($expiresAt !== null) {
            $entry['expiresAt'] = $expiresAt;
        }

        if ($addedAt !== null) {
            $entry['addedAt'] = $addedAt;
        }

        if ($metadata !== []) {
            $entry['metadata'] = $metadata;
        }

        return $entry;
    }

    /**
     * @param FilterTypeGeneric $filter
     */
    public function safelist(string $name, array $filter): self
    {
        $this->assertValidFilter($filter);
        $this->assertValidSafelistFilter($filter);
        $this->schema['safelists'][] = ['name' => $name, 'filter' => $filter];
        return $this;
    }

    /**
     * @param FilterTypeGeneric $filter
     */
    public function blocklist(string $name, array $filter): self
    {
        $this->assertValidFilter($filter);
        $this->schema['blocklists'][] = ['name' => $name, 'filter' => $filter];
        return $this;
    }

    /**
     * Add a throttle rule.
     *
     * The optional `$scope` filter restricts which requests the throttle counts:
     * when given, the throttle is only applied to requests the filter matches
     * (e.g. {@see filterPathPrefix()} for `/api`), and all other requests pass
     * through untouched by this rule. This keeps a per-client throttle from
     * accidentally rate-limiting unrelated traffic and is the building block
     * behind the path-scoped throttles shipped by
     * {@see \Flowd\Phirewall\Preset\Presets}.
     *
     * @param Key $key
     * @param Filter|null $scope Optional request filter limiting which requests are throttled.
     */
    public function throttle(string $name, int $limit, int $period, array $key, bool $sliding = false, ?array $scope = null): self
    {
        $this->assertValidKey($key);
        $entry = ['name' => $name, 'limit' => $limit, 'period' => $period, 'key' => $key];
        if ($sliding) {
            $entry['sliding'] = true;
        }

        if ($scope !== null) {
            $this->assertValidFilter($scope);
            $entry['scope'] = $scope;
        }

        $this->schema['throttles'][] = $entry;
        return $this;
    }

    /**
     * @param FilterTypeGeneric $filter
     * @param Key $key
     */
    public function fail2ban(string $name, int $threshold, int $period, int $ban, array $filter, array $key): self
    {
        $this->assertValidFilter($filter);
        $this->assertValidKey($key);
        $this->schema['fail2bans'][] = [
            'name' => $name,
            'threshold' => $threshold,
            'period' => $period,
            'ban' => $ban,
            'filter' => $filter,
            'key' => $key,
        ];
        return $this;
    }

    /**
     * Add an allow2ban rule: count every request for the extracted key and ban
     * once the threshold is reached within the period.
     *
     * Unlike fail2ban there is no filter — allow2ban is a hard volume cap.
     *
     * @param Key $key
     */
    public function allow2ban(string $name, int $threshold, int $period, int $ban, array $key): self
    {
        $this->assertValidKey($key);
        $this->schema['allow2bans'][] = [
            'name' => $name,
            'threshold' => $threshold,
            'period' => $period,
            'ban' => $ban,
            'key' => $key,
        ];
        return $this;
    }

    /**
     * @param FilterTypeGeneric $filter
     * @param Key $key
     */
    public function track(string $name, int $period, array $filter, array $key, ?int $limit = null): self
    {
        $this->assertValidFilter($filter);
        $this->assertValidKey($key);
        if ($limit !== null && $limit < 1) {
            throw new \InvalidArgumentException(
                sprintf('Track rule "%s" limit must be at least 1, got %d.', $name, $limit)
            );
        }

        $entry = [
            'name' => $name,
            'period' => $period,
            'filter' => $filter,
            'key' => $key,
        ];
        if ($limit !== null) {
            $entry['limit'] = $limit;
        }

        $this->schema['tracks'][] = $entry;
        return $this;
    }

    /**
     * Register a named in-memory pattern backend from a list of portable
     * pattern entries (build them with {@see patternEntry()}).
     *
     * A backend is a reusable catalogue of block patterns (IP, CIDR, path,
     * header, regex). Reference it from a blocklist with
     * {@see blocklistFromBackend()}, or use {@see patternBlocklist()} to do
     * both in one call.
     *
     * @param list<PatternEntryArray> $entries
     */
    public function addPatternBackend(string $name, array $entries): self
    {
        if ($name === '') {
            throw new \InvalidArgumentException('Pattern backend name must not be empty.');
        }

        foreach ($entries as $entry) {
            $this->assertValidPatternEntry(self::requireArray($entry, 'Invalid pattern backend entry'));
        }

        $this->schema['patternBackends'][] = ['name' => $name, 'entries' => array_values($entries)];
        return $this;
    }

    /**
     * Add a blocklist rule that matches against a previously registered
     * pattern backend (see {@see addPatternBackend()}).
     */
    public function blocklistFromBackend(string $name, string $backendName): self
    {
        if ($name === '' || $backendName === '') {
            throw new \InvalidArgumentException('Blocklist name and backend name must not be empty.');
        }

        $this->schema['patternBlocklists'][] = ['name' => $name, 'backend' => $backendName];
        return $this;
    }

    /**
     * Convenience: register a pattern backend and a blocklist that consumes it,
     * both under the same name.
     *
     * @param list<PatternEntryArray> $entries
     */
    public function patternBlocklist(string $name, array $entries): self
    {
        $this->addPatternBackend($name, $entries);
        return $this->blocklistFromBackend($name, $name);
    }

    /**
     * Export the portable schema as an array (JSON-serializable).
     * @return Schema
     */
    public function toArray(): array
    {
        return $this->schema;
    }

    /**
     * Import from a portable schema array.
     *
     * Performs schema-shape validation only. When the array is read from a
     * source the caller does not fully trust (shared filesystems, S3, etcd,
     * config services, repositories accepting external contributions), use
     * {@see toSignedJson()} on the producing side and {@see loadSigned()} on
     * the consuming side to detect tampering before the schema is applied.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $self = new self();
        // Basic shape validation and normalization
        $self->schema['safelists'] = array_values((array)($data['safelists'] ?? []));
        $self->schema['blocklists'] = array_values((array)($data['blocklists'] ?? []));
        $self->schema['throttles'] = array_values((array)($data['throttles'] ?? []));
        $self->schema['fail2bans'] = array_values((array)($data['fail2bans'] ?? []));
        $self->schema['allow2bans'] = array_values((array)($data['allow2bans'] ?? []));
        $self->schema['tracks'] = array_values((array)($data['tracks'] ?? []));
        $self->schema['patternBackends'] = array_values((array)($data['patternBackends'] ?? []));
        $self->schema['patternBlocklists'] = array_values((array)($data['patternBlocklists'] ?? []));
        $options = (array)($data['options'] ?? []);
        // `failOpen` is forwarded to the strictly-typed Config::setFailOpen(bool);
        // a non-bool from decoded JSON (e.g. "failOpen": "false") would otherwise
        // surface as a TypeError when the Config is materialized rather than a transport-level
        // validation error. Silently ignoring it is worse: a mistyped value would
        // fall back to the fail-open default, weakening the policy unnoticed.
        if (array_key_exists('failOpen', $options) && !is_bool($options['failOpen'])) {
            throw new \InvalidArgumentException('PortableConfig option "failOpen" must be a boolean.');
        }

        $self->schema['options'] = $options;
        // Validate content. Every section entry must be a JSON object; a scalar
        // (or other non-array) from decoded JSON is a malformed transport payload
        // and must surface as the documented InvalidArgumentException rather than
        // a raw TypeError from offset access.
        foreach ($self->schema['safelists'] as $safelist) {
            $safelist = self::requireArray($safelist, 'Invalid safelist entry');
            $filter = self::requireArray($safelist['filter'] ?? null, 'Invalid safelist filter');
            $self->assertValidFilter($filter);
            $self->assertValidSafelistFilter($filter);
        }

        foreach ($self->schema['blocklists'] as $blocklist) {
            $blocklist = self::requireArray($blocklist, 'Invalid blocklist entry');
            $self->assertValidFilter(self::requireArray($blocklist['filter'] ?? null, 'Invalid blocklist filter'));
        }

        foreach ($self->schema['throttles'] as $throttle) {
            $throttle = self::requireArray($throttle, 'Invalid throttle entry');
            $self->assertValidKey(self::requireArray($throttle['key'] ?? null, 'Invalid throttle key'));
            if (array_key_exists('scope', $throttle)) {
                $self->assertValidFilter(self::requireArray($throttle['scope'] ?? null, 'Invalid throttle scope'));
            }
        }

        foreach ($self->schema['fail2bans'] as $fail2ban) {
            $fail2ban = self::requireArray($fail2ban, 'Invalid fail2ban entry');
            $self->assertValidFilter(self::requireArray($fail2ban['filter'] ?? null, 'Invalid fail2ban filter'));
            $self->assertValidKey(self::requireArray($fail2ban['key'] ?? null, 'Invalid fail2ban key'));
        }

        foreach ($self->schema['allow2bans'] as $allow2ban) {
            $allow2ban = self::requireArray($allow2ban, 'Invalid allow2ban entry');
            $self->assertValidKey(self::requireArray($allow2ban['key'] ?? null, 'Invalid allow2ban key'));
        }

        foreach ($self->schema['tracks'] as $track) {
            $track = self::requireArray($track, 'Invalid track entry');
            $self->assertValidFilter(self::requireArray($track['filter'] ?? null, 'Invalid track filter'));
            $self->assertValidKey(self::requireArray($track['key'] ?? null, 'Invalid track key'));
        }

        $knownBackendNames = [];
        foreach ($self->schema['patternBackends'] as $backend) {
            $backend = self::requireArray($backend, 'Invalid pattern backend entry');
            if (!is_string($backend['name'] ?? null) || $backend['name'] === '') {
                throw new \InvalidArgumentException('Pattern backend requires a non-empty "name".');
            }

            $entries = $backend['entries'] ?? null;
            if (!is_array($entries)) {
                throw new \InvalidArgumentException('Pattern backend "entries" must be a list.');
            }

            foreach ($entries as $entry) {
                $self->assertValidPatternEntry(self::requireArray($entry, 'Invalid pattern backend entry'));
            }

            $knownBackendNames[$backend['name']] = true;
        }

        foreach ($self->schema['patternBlocklists'] as $patternBlocklist) {
            $patternBlocklist = self::requireArray($patternBlocklist, 'Invalid pattern blocklist entry');
            if (!is_string($patternBlocklist['name'] ?? null) || $patternBlocklist['name'] === '') {
                throw new \InvalidArgumentException('Pattern blocklist requires a non-empty "name".');
            }

            if (!is_string($patternBlocklist['backend'] ?? null) || $patternBlocklist['backend'] === '') {
                throw new \InvalidArgumentException('Pattern blocklist requires a non-empty "backend" reference.');
            }

            // Cross-check the reference now so a dangling backend fails at load
            // time rather than later when the Config is materialized.
            if (!isset($knownBackendNames[$patternBlocklist['backend']])) {
                throw new \InvalidArgumentException(sprintf(
                    'Pattern blocklist "%s" references unknown pattern backend "%s".',
                    $patternBlocklist['name'],
                    $patternBlocklist['backend'],
                ));
            }
        }

        return $self;
    }

    /**
     * Export the portable schema as a signed JWS-compact-style string.
     *
     * The output has the shape `<header>.<payload>.<signature>` where:
     *   - `<header>` is a base64url-encoded JSON object {"alg":"HS256","typ":"phirewall.config.v1"}
     *   - `<payload>` is base64url-encoded JSON of {@see toArray()}
     *   - `<signature>` is base64url-encoded HMAC-SHA256 of `<header>.<payload>`
     *
     * Consumers verify the signature with {@see loadSigned()} before applying
     * the rules. Use this whenever the serialized config crosses a trust
     * boundary (a writable filesystem, S3 bucket, etcd, config service, git
     * repository accepting external contributions, etc.) — even when the
     * channel itself is considered "internal".
     *
     * @param string $secretKey HMAC key; SHOULD be at least 32 random bytes.
     *                          Keys shorter than 16 bytes are rejected to
     *                          prevent accidental misuse of short / empty
     *                          strings as a key.
     */
    public function toSignedJson(string $secretKey): string
    {
        if (strlen($secretKey) < self::MIN_SECRET_KEY_LENGTH) {
            throw new \InvalidArgumentException(sprintf(
                'PortableConfig signing key must be at least %d bytes; use random_bytes(32) or a comparable CSPRNG output.',
                self::MIN_SECRET_KEY_LENGTH,
            ));
        }

        $header = $this->base64UrlEncode(json_encode(
            ['alg' => 'HS256', 'typ' => self::SIGNED_TYPE],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        ));
        $payload = $this->base64UrlEncode(json_encode(
            $this->schema,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        ));
        $signingInput = $header . '.' . $payload;
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $signingInput, $secretKey, true));

        return $signingInput . '.' . $signature;
    }

    /**
     * Load and verify a signed PortableConfig previously produced by
     * {@see toSignedJson()}.
     *
     * The signature is checked with {@see hash_equals()} for constant-time
     * comparison. Any tampering with the header, payload, or signature
     * — including key substitution, algorithm downgrade attempts, and
     * payload re-ordering — causes a {@see \RuntimeException}.
     *
     * @throws \InvalidArgumentException When the input is structurally invalid
     *                                   (short key, wrong segment count, base64
     *                                   corruption, non-JSON or non-object payload).
     * @throws \RuntimeException When the signature does not verify, or the header
     *                           is malformed or declares an unsupported alg/typ.
     */
    public static function loadSigned(string $signedJson, string $secretKey): self
    {
        if (strlen($secretKey) < self::MIN_SECRET_KEY_LENGTH) {
            throw new \InvalidArgumentException(sprintf(
                'PortableConfig signing key must be at least %d bytes; use random_bytes(32) or a comparable CSPRNG output.',
                self::MIN_SECRET_KEY_LENGTH,
            ));
        }

        // Bounded split (limit 4) so attacker-controlled input with many dots
        // cannot allocate a huge array; a valid envelope has exactly three
        // segments, so any extra dot produces a 4th element and is rejected.
        $parts = explode('.', $signedJson, 4);
        if (count($parts) !== 3) {
            throw new \InvalidArgumentException('Signed PortableConfig must have three "."-separated segments (header.payload.signature).');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $signingInput = $encodedHeader . '.' . $encodedPayload;

        $headerJson = self::base64UrlDecode($encodedHeader);
        if ($headerJson === null) {
            throw new \InvalidArgumentException('Signed PortableConfig header is not valid base64url.');
        }

        try {
            /** @var mixed $header */
            $header = json_decode($headerJson, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            throw new \InvalidArgumentException('Signed PortableConfig header is not valid JSON.', $jsonException->getCode(), previous: $jsonException);
        }

        if (!is_array($header)
            || ($header['alg'] ?? null) !== 'HS256'
            || ($header['typ'] ?? null) !== self::SIGNED_TYPE
        ) {
            throw new \RuntimeException('Signed PortableConfig header is unsupported or malformed (expected alg=HS256, typ=' . self::SIGNED_TYPE . ').');
        }

        $expectedSignature = hash_hmac('sha256', $signingInput, $secretKey, true);
        $providedSignature = self::base64UrlDecode($encodedSignature);
        if ($providedSignature === null) {
            throw new \InvalidArgumentException('Signed PortableConfig signature is not valid base64url.');
        }

        if (!hash_equals($expectedSignature, $providedSignature)) {
            throw new \RuntimeException('Signed PortableConfig signature verification failed: content was tampered with or signed with a different key.');
        }

        $payloadJson = self::base64UrlDecode($encodedPayload);
        if ($payloadJson === null) {
            throw new \InvalidArgumentException('Signed PortableConfig payload is not valid base64url.');
        }

        try {
            /** @var mixed $payload */
            $payload = json_decode($payloadJson, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            throw new \InvalidArgumentException('Signed PortableConfig payload is not valid JSON.', $jsonException->getCode(), previous: $jsonException);
        }

        // The payload is the PortableConfig schema as a JSON object. A producer
        // need only include the sections it actually sets — fromArray() defaults
        // every absent section to empty — so an object with a subset of keys, or
        // an empty object (a no-op config), is valid. Reject only a non-object
        // payload: a scalar/null, or a JSON list (a non-empty sequential array).
        if (!is_array($payload) || (array_is_list($payload) && $payload !== [])) {
            throw new \InvalidArgumentException('Signed PortableConfig payload must decode to a JSON object, not a list.');
        }

        // A structurally malformed (but validly-signed) payload — e.g. a scalar
        // where a section array is expected — can make fromArray() raise a
        // TypeError on offset access. Normalize it to the documented
        // InvalidArgumentException so consumers get a consistent validation
        // error rather than an unexpected crash across the transport boundary.
        try {
            return self::fromArray($payload);
        } catch (\TypeError $typeError) {
            throw new \InvalidArgumentException('Signed PortableConfig payload is structurally invalid: ' . $typeError->getMessage(), $typeError->getCode(), previous: $typeError);
        }
    }

    /**
     * Apply this schema's rules and options to the given Config and return it.
     *
     * Rules are registered through the section API
     * ({@see Config::$safelists}, {@see Config::$blocklists}, …) rather than the
     * deprecated forwarding methods, and dedicated matchers ({@see IpMatcher},
     * {@see KnownScannerMatcher}, …) are used where a filter maps onto one.
     *
     * @internal Materialize a PortableConfig through {@see Config::combine()},
     *           which supplies the Config (and therefore the cache) — the
     *           portable/preset layer never receives a cache itself.
     */
    public function applyTo(Config $config): Config
    {
        $options = $this->schema['options'];
        if (isset($options['rateLimitHeaders']) && $options['rateLimitHeaders']) {
            $config->enableRateLimitHeaders(true);
        }

        if (isset($options['responseHeaders']) && $options['responseHeaders']) {
            $config->enableResponseHeaders(true);
        }

        if (isset($options['owaspDiagnosticsHeader']) && $options['owaspDiagnosticsHeader']) {
            $config->enableOwaspDiagnosticsHeader(true);
        }

        if (array_key_exists('failOpen', $options)) {
            $config->setFailOpen($options['failOpen']);
        }

        if (isset($options['keyPrefix']) && is_string($options['keyPrefix'])) {
            $config->setKeyPrefix($options['keyPrefix']);
        }

        // Safelists
        foreach ($this->schema['safelists'] as $safelist) {
            $config->safelists->addRule(new SafelistRule(
                $safelist['name'],
                $this->compileFilterMatcher($safelist['filter']),
            ));
        }

        // Blocklists
        foreach ($this->schema['blocklists'] as $blocklist) {
            $config->blocklists->addRule(new BlocklistRule(
                $blocklist['name'],
                $this->compileFilterMatcher($blocklist['filter']),
            ));
        }

        // Throttles
        foreach ($this->schema['throttles'] as $throttle) {
            $keyExtractor = $this->compileKey($throttle['key']);
            if (isset($throttle['scope'])) {
                $keyExtractor = $this->scopeKeyExtractor($keyExtractor, $this->compileFilterMatcher($throttle['scope']));
            }

            $config->throttles->addRule(new ThrottleRule(
                $throttle['name'],
                (int)$throttle['limit'],
                (int)$throttle['period'],
                new ClosureKeyExtractor($keyExtractor),
                ($throttle['sliding'] ?? false) === true,
            ));
        }

        // Fail2Ban
        foreach ($this->schema['fail2bans'] as $fail2ban) {
            $config->fail2ban->addRule(new Fail2BanRule(
                $fail2ban['name'],
                (int)$fail2ban['threshold'],
                (int)$fail2ban['period'],
                (int)$fail2ban['ban'],
                $this->compileFilterMatcher($fail2ban['filter']),
                new ClosureKeyExtractor($this->compileKey($fail2ban['key'])),
            ));
        }

        // Allow2Ban
        foreach ($this->schema['allow2bans'] as $allow2ban) {
            $config->allow2ban->addRule(new Allow2BanRule(
                $allow2ban['name'],
                (int)$allow2ban['threshold'],
                (int)$allow2ban['period'],
                (int)$allow2ban['ban'],
                new ClosureKeyExtractor($this->compileKey($allow2ban['key'])),
            ));
        }

        // Tracks
        foreach ($this->schema['tracks'] as $track) {
            $trackLimit = isset($track['limit']) ? (int) $track['limit'] : null;
            $config->tracks->addRule(new TrackRule(
                $track['name'],
                (int)$track['period'],
                $this->compileFilterMatcher($track['filter']),
                new ClosureKeyExtractor($this->compileKey($track['key'])),
                $trackLimit,
            ));
        }

        // Pattern backends + blocklists that consume them
        foreach ($this->schema['patternBackends'] as $backend) {
            $config->blocklists->addPatternBackend(
                $backend['name'],
                new InMemoryPatternBackend($this->compilePatternEntries($backend['entries'])),
            );
        }

        foreach ($this->schema['patternBlocklists'] as $patternBlocklist) {
            $config->blocklists->fromBackend($patternBlocklist['name'], $patternBlocklist['backend']);
        }

        return $config;
    }

    /**
     * @param Filter $filter
     */
    private function compileFilterMatcher(array $filter): RequestMatcherInterface
    {
        $type = (string)($filter['type'] ?? '');
        return match ($type) {
            'ip' => new IpMatcher(self::toStringList($filter['ips'] ?? [])),
            'known_scanners' => new KnownScannerMatcher(isset($filter['patterns']) ? self::toStringList($filter['patterns']) : null),
            'suspicious_headers' => new SuspiciousHeadersMatcher(isset($filter['headers']) ? self::toStringList($filter['headers']) : null),
            default => new ClosureRequestMatcher($this->compileFilterClosure($filter)),
        };
    }

    /**
     * Compile the request-predicate filter types into a closure.
     *
     * @param Filter $filter
     * @return \Closure(ServerRequestInterface): bool
     */
    private function compileFilterClosure(array $filter): \Closure
    {
        $type = (string)($filter['type'] ?? '');
        return match ($type) {
            'path_equals' => static function (ServerRequestInterface $serverRequest) use ($filter): bool {
                $path = (string)($filter['path'] ?? '/');
                return $serverRequest->getUri()->getPath() === $path;
            },
            'path_prefix' => static function (ServerRequestInterface $serverRequest) use ($filter): bool {
                $prefix = (string)($filter['prefix'] ?? '');
                return $prefix !== '' && str_starts_with($serverRequest->getUri()->getPath(), $prefix);
            },
            'path_regex' => (static function () use ($filter): \Closure {
                $pattern = RegexMatcher::compile((string)($filter['pattern'] ?? ''));
                return static fn(ServerRequestInterface $serverRequest): bool => RegexMatcher::matches($pattern, $serverRequest->getUri()->getPath());
            })(),
            'method_equals' => static function (ServerRequestInterface $serverRequest) use ($filter): bool {
                $method = strtoupper((string)($filter['method'] ?? ''));
                return strtoupper($serverRequest->getMethod()) === $method;
            },
            'method_in' => (static function () use ($filter): \Closure {
                $methods = array_map(static fn(string $method): string => strtoupper($method), self::toStringList($filter['methods'] ?? []));
                return static fn(ServerRequestInterface $serverRequest): bool => in_array(strtoupper($serverRequest->getMethod()), $methods, true);
            })(),
            'header_equals' => static function (ServerRequestInterface $serverRequest) use ($filter): bool {
                $name = (string)($filter['name'] ?? '');
                $value = (string)($filter['value'] ?? '');
                return $name !== '' && hash_equals($value, $serverRequest->getHeaderLine($name));
            },
            'header_present' => static function (ServerRequestInterface $serverRequest) use ($filter): bool {
                $name = (string)($filter['name'] ?? '');
                return $name !== '' && $serverRequest->getHeaderLine($name) !== '';
            },
            'header_regex' => (static function () use ($filter): \Closure {
                $name = (string)($filter['name'] ?? '');
                $pattern = RegexMatcher::compile((string)($filter['pattern'] ?? ''));
                return static fn(ServerRequestInterface $serverRequest): bool => $name !== '' && RegexMatcher::matches($pattern, $serverRequest->getHeaderLine($name));
            })(),
            'all' => static fn(ServerRequestInterface $serverRequest): bool => true,
            'none' => static fn(ServerRequestInterface $serverRequest): bool => false,
            default => throw new \InvalidArgumentException('Unsupported filter type: ' . $type),
        };
    }

    /** @param array<string,scalar> $key */
    private function compileKey(array $key): \Closure
    {
        $type = (string)($key['type'] ?? '');
        return match ($type) {
            'ip' => KeyExtractors::ip(),
            'method' => KeyExtractors::method(),
            'path' => KeyExtractors::path(),
            'header' => (static fn(string $name): \Closure => KeyExtractors::header($name))((string)($key['name'] ?? '')),
            'hashed_header' => (static fn(string $name): \Closure => KeyExtractors::hashedHeader($name))((string)($key['name'] ?? '')),
            default => throw new \InvalidArgumentException('Unsupported key extractor type: ' . $type),
        };
    }

    /**
     * Wrap a key extractor so it only yields a discriminator when the request
     * matches the scope filter. When the filter does not match, the extractor
     * returns null and the throttle evaluator skips the rule for that request.
     *
     * @param \Closure(ServerRequestInterface): ?string $keyExtractor
     * @return \Closure(ServerRequestInterface): ?string
     */
    private function scopeKeyExtractor(\Closure $keyExtractor, RequestMatcherInterface $requestMatcher): \Closure
    {
        return static function (ServerRequestInterface $serverRequest) use ($keyExtractor, $requestMatcher): ?string {
            if (!$requestMatcher->match($serverRequest)->isMatch()) {
                return null;
            }

            return $keyExtractor($serverRequest);
        };
    }

    /**
     * @param list<PatternEntryArray> $entries
     * @return list<PatternEntry>
     */
    private function compilePatternEntries(array $entries): array
    {
        $compiled = [];
        foreach ($entries as $entry) {
            $metadata = $entry['metadata'] ?? [];
            $compiled[] = new PatternEntry(
                kind: PatternKind::from($entry['kind']),
                value: $entry['value'],
                target: $entry['target'] ?? null,
                expiresAt: $entry['expiresAt'] ?? null,
                addedAt: $entry['addedAt'] ?? null,
                metadata: $metadata,
            );
        }

        return $compiled;
    }

    /**
     * @return list<string>
     */
    private static function toStringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $strings = [];
        foreach ($value as $item) {
            if (is_string($item)) {
                $strings[] = $item;
            }
        }

        return $strings;
    }

    /**
     * Narrow a decoded-schema value to an array or fail with a transport-level
     * validation error. Decoded JSON can place a scalar where the schema expects
     * an object; without this guard the later offset access would raise a raw
     * TypeError instead of the documented InvalidArgumentException.
     *
     * @return array<string, mixed>
     */
    private static function requireArray(mixed $value, string $message): array
    {
        if (!is_array($value)) {
            throw new \InvalidArgumentException($message);
        }

        /** @var array<string, mixed> $value */
        return $value;
    }

    /**
     * Validate a builder-supplied list so the static filter builders can never
     * emit a schema that {@see fromArray()} would later reject (empty lists) or
     * that would silently compile into a no-op matcher. Keeps the builder output
     * consistent with the transport validator and the toArray()/fromArray()
     * round-trip.
     *
     * @param array<array-key, mixed> $values
     * @return list<string>
     */
    private static function requireNonEmptyStringList(array $values, string $context): array
    {
        if ($values === []) {
            throw new \InvalidArgumentException($context . ' requires a non-empty list of values.');
        }

        $list = [];
        foreach ($values as $value) {
            if (!is_string($value) || trim($value) === '') {
                throw new \InvalidArgumentException($context . ' requires non-empty string values.');
            }

            $list[] = $value;
        }

        return $list;
    }

    /** @param array<string,mixed> $filter */
    private function assertValidFilter(array $filter): void
    {
        $type = $filter['type'] ?? null;
        $known = [
            'all',
            'none',
            'path_equals',
            'path_prefix',
            'path_regex',
            'method_equals',
            'method_in',
            'header_equals',
            'header_present',
            'header_regex',
            'ip',
            'known_scanners',
            'suspicious_headers',
        ];
        if (!in_array($type, $known, true)) {
            throw new \InvalidArgumentException('Invalid filter type');
        }

        if ($type === 'path_equals' && !is_string($filter['path'] ?? null)) {
            throw new \InvalidArgumentException('path_equals requires path');
        }

        if ($type === 'path_prefix' && !is_string($filter['prefix'] ?? null)) {
            throw new \InvalidArgumentException('path_prefix requires prefix');
        }

        if ($type === 'method_equals' && !is_string($filter['method'] ?? null)) {
            throw new \InvalidArgumentException('method_equals requires method');
        }

        if ($type === 'method_in' && !$this->isStringList($filter['methods'] ?? null)) {
            throw new \InvalidArgumentException('method_in requires a non-empty list of method strings');
        }

        if ($type === 'header_equals' && (!is_string($filter['name'] ?? null) || !is_string($filter['value'] ?? null))) {
            throw new \InvalidArgumentException('header_equals requires name and value');
        }

        if ($type === 'header_present' && !is_string($filter['name'] ?? null)) {
            throw new \InvalidArgumentException('header_present requires name');
        }

        if (($type === 'path_regex' || $type === 'header_regex')) {
            if ($type === 'header_regex' && !is_string($filter['name'] ?? null)) {
                throw new \InvalidArgumentException('header_regex requires name');
            }

            $pattern = $filter['pattern'] ?? null;
            if (!is_string($pattern) || RegexMatcher::compile($pattern) === null) {
                throw new \InvalidArgumentException($type . ' requires a valid PCRE pattern (delimiters included)');
            }
        }

        if ($type === 'ip' && !$this->isStringList($filter['ips'] ?? null)) {
            throw new \InvalidArgumentException('ip filter requires a non-empty list of IP/CIDR strings');
        }

        if ($type === 'known_scanners' && isset($filter['patterns']) && !$this->isStringList($filter['patterns'])) {
            throw new \InvalidArgumentException('known_scanners patterns must be a list of strings');
        }

        if ($type === 'suspicious_headers' && isset($filter['headers']) && !$this->isStringList($filter['headers'])) {
            throw new \InvalidArgumentException('suspicious_headers headers must be a list of strings');
        }
    }

    /**
     * Additional safelist-only checks.
     *
     * Header-based filters (`header_equals`, `header_present`, `header_regex`)
     * are not permitted in safelists: the header value is client-controlled,
     * so a safelist keyed on it is a forgeable bypass token (anyone presenting
     * the header skips every downstream rule), and any literal value sits in
     * the rules file in plaintext. The `header` key extractor on throttle /
     * fail2ban / track rules is still allowed because those rules apply
     * restrictions rather than bypassing them.
     *
     * @param array<string,mixed> $filter
     */
    private function assertValidSafelistFilter(array $filter): void
    {
        $type = $filter['type'] ?? null;
        if (is_string($type) && str_starts_with($type, 'header_')) {
            throw new \InvalidArgumentException(
                'header_equals, header_present and header_regex filters are not allowed for safelists: '
                . 'the header value is client-controlled and can be forged to bypass every downstream rule. '
                . 'Use an authenticated principal or an IP-based filter instead.'
            );
        }
    }

    /** @param array<string,mixed> $key */
    private function assertValidKey(array $key): void
    {
        $type = $key['type'] ?? null;
        if (!in_array($type, ['ip', 'method', 'path', 'header', 'hashed_header'], true)) {
            throw new \InvalidArgumentException('Invalid key extractor type');
        }

        if (($type === 'header' || $type === 'hashed_header') && (!is_string($key['name'] ?? null) || $key['name'] === '')) {
            throw new \InvalidArgumentException($type . ' key extractor requires a non-empty name');
        }
    }

    /** @param array<string,mixed> $entry */
    private function assertValidPatternEntry(array $entry): void
    {
        $kind = $entry['kind'] ?? null;
        if (!is_string($kind) || !(PatternKind::tryFrom($kind) instanceof PatternKind)) {
            throw new \InvalidArgumentException('Invalid pattern entry kind: ' . (is_string($kind) ? $kind : gettype($kind)));
        }

        $value = $entry['value'] ?? null;
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException(sprintf('Pattern entry "%s" requires a non-empty string value.', $kind));
        }

        $target = $entry['target'] ?? null;
        if ($target !== null && !is_string($target)) {
            throw new \InvalidArgumentException(sprintf('Pattern entry "%s" target must be a string or null.', $kind));
        }

        if (($kind === PatternKind::HEADER_EXACT->value || $kind === PatternKind::HEADER_REGEX->value)
            && (!is_string($target) || $target === '')
        ) {
            throw new \InvalidArgumentException(sprintf('Pattern entry "%s" requires a non-empty target (header name).', $kind));
        }

        foreach (['expiresAt', 'addedAt'] as $timestampField) {
            if (isset($entry[$timestampField]) && !is_int($entry[$timestampField])) {
                throw new \InvalidArgumentException(sprintf('Pattern entry "%s" %s must be an integer timestamp.', $kind, $timestampField));
            }
        }

        $metadata = $entry['metadata'] ?? [];
        if (!is_array($metadata)) {
            throw new \InvalidArgumentException(sprintf('Pattern entry "%s" metadata must be an array of scalars.', $kind));
        }

        foreach ($metadata as $metadataValue) {
            if (!is_scalar($metadataValue)) {
                throw new \InvalidArgumentException(sprintf('Pattern entry "%s" metadata values must be scalar.', $kind));
            }
        }

        if (in_array($kind, [PatternKind::PATH_REGEX->value, PatternKind::HEADER_REGEX->value, PatternKind::REQUEST_REGEX->value], true)
            && RegexMatcher::compile($value) === null
        ) {
            throw new \InvalidArgumentException(sprintf('Pattern entry "%s" requires a valid PCRE pattern (delimiters included).', $kind));
        }
    }

    /**
     * @phpstan-assert-if-true non-empty-list<string> $value
     */
    private function isStringList(mixed $value): bool
    {
        if (!is_array($value) || $value === [] || !array_is_list($value)) {
            return false;
        }

        foreach ($value as $item) {
            if (!is_string($item) || trim($item) === '') {
                return false;
            }
        }

        return true;
    }

    private function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $encoded): ?string
    {
        $padded = strtr($encoded, '-_', '+/');
        $remainder = strlen($padded) % 4;
        if ($remainder === 1) {
            // A base64 string can never have length % 4 == 1; reject rather
            // than pad an inherently invalid input.
            return null;
        }

        if ($remainder !== 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($padded, true);
        return $decoded === false ? null : $decoded;
    }
}
