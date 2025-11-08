<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Portable;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * A portable representation of firewall rules that can be exported/imported as arrays (or JSON).
 *
 * Scope: Supports a constrained, safe subset of rule definitions using named extractors and simple filters.
 * This avoids serializing arbitrary closures while enabling sharing of common rule sets across apps/processes.
 */
/**
 * @phpstan-type FilterTypeGeneric array{type: string}
 * @phpstan-type FilterTypeAll array{type: 'all'}
 * @phpstan-type FilterMethodEquals FilterTypeGeneric&array{type: 'method_equals', method: string}
 * @phpstan-type FilterPathEquals FilterTypeGeneric&array{type: 'path_equals', path: string}
 * @phpstan-type FilterHeaderEquals FilterTypeGeneric&array{type: 'header_equals', name: string, value: string}
 * @phpstan-type Filter FilterMethodEquals|FilterPathEquals|FilterHeaderEquals|FilterTypeGeneric|FilterTypeAll
 * @phpstan-type Key array{type: 'ip'}|array{type: 'method'}|array{type: 'path'}|array{type: 'header', name: string}
 * @phpstan-type SchemaSafelists list<array{name: string, filter: Filter}>
 * @phpstan-type SchemaBlocklists list<array{name: string, filter: Filter}>
 * @phpstan-type SchemaThrottles list<array{name: string, limit: int, period: int, key: Key}>
 * @phpstan-type SchemaFail2Bans list<array{name: string, threshold: int, period: int, ban: int, filter: Filter, key: Key}>
 * @phpstan-type SchemaTracks list<array{name: string, period: int, filter: Filter, key: Key}>
 * @phpstan-type SchemaOptions array{rateLimitHeaders?: bool, keyPrefix?: string}
 * @phpstan-type Schema array{
 *   safelists: SchemaSafelists,
 *   blocklists: SchemaBlocklists,
 *   throttles: SchemaThrottles,
 *   fail2bans: SchemaFail2Bans,
 *   tracks: SchemaTracks,
 *   options: SchemaOptions
 * }
 */
final class PortableConfig
{
    /** @var Schema */
    private array $schema = [
        'safelists' => [],
        'blocklists' => [],
        'throttles' => [],
        'fail2bans' => [],
        'tracks' => [],
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

    public function setKeyPrefix(string $prefix): self
    {
        $this->schema['options']['keyPrefix'] = $prefix;
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
     * @return Key
     */
    public static function keyIp(): array
    {
        return ['type' => 'ip'];
    }

    /**
     * @return Key
     */
    public static function keyMethod(): array
    {
        return ['type' => 'method'];
    }

    /**
     * @return Key
     */
    public static function keyPath(): array
    {
        return ['type' => 'path'];
    }

    /**
     * @return Key
     */
    public static function keyHeader(string $name): array
    {
        return ['type' => 'header', 'name' => $name];
    }

    /**
     * @param FilterTypeGeneric $filter
     */
    public function safelist(string $name, array $filter): self
    {
        $this->assertValidFilter($filter);
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
     * @param Key $key
     */
    public function throttle(string $name, int $limit, int $period, array $key): self
    {
        $this->assertValidKey($key);
        $this->schema['throttles'][] = ['name' => $name, 'limit' => $limit, 'period' => $period, 'key' => $key];
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
     * @param FilterTypeGeneric $filter
     * @param Key $key
     */
    public function track(string $name, int $period, array $filter, array $key): self
    {
        $this->assertValidFilter($filter);
        $this->assertValidKey($key);
        $this->schema['tracks'][] = [
            'name' => $name,
            'period' => $period,
            'filter' => $filter,
            'key' => $key,
        ];
        return $this;
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
        $self->schema['tracks'] = array_values((array)($data['tracks'] ?? []));
        $self->schema['options'] = (array)($data['options'] ?? []);
        // Validate content
        foreach ($self->schema['safelists'] as $s) {
            if (!is_array($s)) {
                continue;
            }

            $self->assertValidFilter($s['filter']);
        }

        foreach ($self->schema['blocklists'] as $b) {
            $self->assertValidFilter($b['filter']);
        }

        foreach ($self->schema['throttles'] as $t) {
            $self->assertValidKey($t['key']);
        }

        foreach ($self->schema['fail2bans'] as $f) {
            $self->assertValidFilter($f['filter']);
            $self->assertValidKey($f['key']);
        }

        foreach ($self->schema['tracks'] as $t) {
            $self->assertValidFilter($t['filter']);
            $self->assertValidKey($t['key']);
        }

        return $self;
    }

    /**
     * Build a Config instance with closures derived from the portable schema.
     */
    public function toConfig(CacheInterface $cache, ?EventDispatcherInterface $eventDispatcher = null): Config
    {
        $config = new Config($cache, $eventDispatcher);
        $options = $this->schema['options'];
        if (isset($options['rateLimitHeaders']) && $options['rateLimitHeaders']) {
            $config->enableRateLimitHeaders(true);
        }

        if (isset($options['keyPrefix']) && is_string($options['keyPrefix'])) {
            $config->setKeyPrefix($options['keyPrefix']);
        }

        // Safelists
        foreach ($this->schema['safelists'] as $s) {
            $config->addSafelist(new \Flowd\Phirewall\Config\Rule\SafelistRule(
                $s['name'],
                new \Flowd\Phirewall\Config\ClosureRequestMatcher($this->compileFilter($s['filter']))
            ));
        }

        // Blocklists
        foreach ($this->schema['blocklists'] as $b) {
            $config->addBlocklist(new \Flowd\Phirewall\Config\Rule\BlocklistRule(
                $b['name'],
                new \Flowd\Phirewall\Config\ClosureRequestMatcher($this->compileFilter($b['filter']))
            ));
        }

        // Throttles
        foreach ($this->schema['throttles'] as $t) {
            $config->addThrottle(new \Flowd\Phirewall\Config\Rule\ThrottleRule(
                $t['name'],
                (int)$t['limit'],
                (int)$t['period'],
                new \Flowd\Phirewall\Config\ClosureKeyExtractor($this->compileKey($t['key']))
            ));
        }

        // Fail2Ban
        foreach ($this->schema['fail2bans'] as $f) {
            $config->addFail2Ban(new \Flowd\Phirewall\Config\Rule\Fail2BanRule(
                $f['name'],
                (int)$f['threshold'],
                (int)$f['period'],
                (int)$f['ban'],
                new \Flowd\Phirewall\Config\ClosureRequestMatcher($this->compileFilter($f['filter'])),
                new \Flowd\Phirewall\Config\ClosureKeyExtractor($this->compileKey($f['key']))
            ));
        }

        // Tracks
        foreach ($this->schema['tracks'] as $t) {
            $config->addTrack(new \Flowd\Phirewall\Config\Rule\TrackRule(
                $t['name'],
                (int)$t['period'],
                new \Flowd\Phirewall\Config\ClosureRequestMatcher($this->compileFilter($t['filter'])),
                new \Flowd\Phirewall\Config\ClosureKeyExtractor($this->compileKey($t['key']))
            ));
        }

        return $config;
    }

    /**
     * @param Filter $filter
     */
    private function compileFilter(array $filter): \Closure
    {
        $type = (string)($filter['type'] ?? '');
        return match ($type) {
            'path_equals' => static function (\Psr\Http\Message\ServerRequestInterface $serverRequest) use ($filter): bool {
                $path = (string)($filter['path'] ?? '/');
                return $serverRequest->getUri()->getPath() === $path;
            },
            'method_equals' => static function (\Psr\Http\Message\ServerRequestInterface $serverRequest) use ($filter): bool {
                $method = strtoupper((string)($filter['method'] ?? ''));
                return strtoupper($serverRequest->getMethod()) === $method;
            },
            'header_equals' => static function (\Psr\Http\Message\ServerRequestInterface $serverRequest) use ($filter): bool {
                $name = (string)($filter['name'] ?? '');
                $value = (string)($filter['value'] ?? '');
                return $name !== '' && $serverRequest->getHeaderLine($name) === $value;
            },
            'all' => static fn(): bool => true,
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
            default => throw new \InvalidArgumentException('Unsupported key extractor type: ' . $type),
        };
    }

    /** @param array<string,mixed> $filter */
    private function assertValidFilter(array $filter): void
    {
        $type = $filter['type'] ?? null;
        if (!in_array($type, ['path_equals', 'method_equals', 'header_equals', 'all'], true)) {
            throw new \InvalidArgumentException('Invalid filter type');
        }

        if ($type === 'path_equals' && !is_string($filter['path'] ?? null)) {
            throw new \InvalidArgumentException('path_equals requires path');
        }

        if ($type === 'method_equals' && !is_string($filter['method'] ?? null)) {
            throw new \InvalidArgumentException('method_equals requires method');
        }

        if ($type === 'header_equals' && (!is_string($filter['name'] ?? null) || !is_string($filter['value'] ?? null))) {
            throw new \InvalidArgumentException('header_equals requires name and value');
        }
    }

    /** @param array<string,mixed> $key */
    private function assertValidKey(array $key): void
    {
        $type = $key['type'] ?? null;
        if (!in_array($type, ['ip', 'method', 'path', 'header'], true)) {
            throw new \InvalidArgumentException('Invalid key extractor type');
        }

        if ($type === 'header' && !is_string($key['name'] ?? null)) {
            throw new \InvalidArgumentException('header key extractor requires name');
        }
    }
}
