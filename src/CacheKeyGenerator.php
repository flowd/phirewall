<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

final class CacheKeyGenerator
{
    /** @var array<string, string> */
    private array $cache = [];

    public function __construct(private readonly string $prefix)
    {
    }

    public function throttleKey(string $name, string $key): string
    {
        return $this->prefix . ':throttle:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    public function fail2BanFailKey(string $name, string $key): string
    {
        return $this->prefix . ':fail2ban:fail:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    public function fail2BanBanKey(string $name, string $key): string
    {
        return $this->prefix . ':fail2ban:ban:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    public function allow2BanHitKey(string $name, string $key): string
    {
        return $this->prefix . ':allow2ban:hit:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    public function allow2BanBanKey(string $name, string $key): string
    {
        return $this->prefix . ':allow2ban:ban:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    public function trackKey(string $name, string $key): string
    {
        return $this->prefix . ':track:' . $this->normalizeName($name) . ':' . $this->hashKey($key);
    }

    /**
     * Build the registry cache key used by BanManager.
     */
    public function banRegistryKey(string $type, string $ruleName): string
    {
        return $this->prefix . ':ban-registry:' . $type . ':' . $this->normalizeName($ruleName);
    }

    /**
     * Normalize a rule name for use in cache keys (human-readable, safe characters).
     */
    public function normalizeName(string $name): string
    {
        $cacheKey = 'n:' . $name;

        return $this->cache[$cacheKey] ??= $this->doNormalize($name);
    }

    /**
     * Hash a user-extracted key for use in cache keys (collision-free).
     *
     * Not memoized: user-extracted keys are unbounded (IPs, tokens, etc.)
     * and caching them would grow without limit in long-lived processes.
     */
    public function hashKey(string $key): string
    {
        return hash('sha256', $key);
    }

    private function doNormalize(string $value): string
    {
        $original = trim($value);
        if ($original === '') {
            return 'empty';
        }

        $sanitized = preg_replace('/[^A-Za-z0-9._:-]/', '_', $original);
        if ($sanitized === null) {
            $sanitized = 'invalid';
        }

        $sanitized = preg_replace('/_+/', '_', $sanitized) ?? $sanitized;
        $max = 120;
        if (strlen($sanitized) > $max) {
            $hash = substr(sha1($original), 0, 12);
            $sanitized = substr($sanitized, 0, $max - 13) . '-' . $hash;
        }

        return $sanitized;
    }
}
