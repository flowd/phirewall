<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Psr\SimpleCache\CacheInterface;

final readonly class BanManager
{
    private const VALID_TYPES = ['allow2ban', 'fail2ban'];

    public function __construct(private Config $config)
    {
    }

    /**
     * Register a ban in the ban registry. Called by Firewall when a ban is set.
     *
     * @param CacheInterface $cache The cache store
     * @param string $prefix The key prefix (e.g. 'phirewall')
     * @param string $type 'allow2ban' or 'fail2ban'
     * @param string $ruleName The rule name
     * @param string $key The original (unhashed) key value (e.g. IP address)
     * @param float $expiresAt microtime(true) + banSeconds
     */
    public static function registerBan(
        CacheInterface $cache,
        string $prefix,
        string $type,
        string $ruleName,
        string $key,
        float $expiresAt,
    ): void {
        $registryKey = self::registryKey($prefix, $type, $ruleName);

        /** @var array<string, float> $registry */
        $registry = [];
        $existing = $cache->get($registryKey);
        if (is_string($existing)) {
            $decoded = json_decode($existing, true);
            if (is_array($decoded)) {
                /** @var array<string, float> $registry */
                $registry = $decoded;
            }
        }

        $registry[$key] = $expiresAt;

        $cache->set($registryKey, json_encode($registry, JSON_THROW_ON_ERROR));
    }

    /**
     * Check if a specific key is currently banned for a rule.
     */
    public function isBanned(string $ruleName, string $key, string $type = 'allow2ban'): bool
    {
        $this->assertValidType($type);

        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($type, $ruleName, $key);

        return $cache->has($banKey);
    }

    /**
     * Unban a specific key for a rule. Returns true if the key was banned.
     */
    public function unban(string $ruleName, string $key, string $type = 'allow2ban'): bool
    {
        $this->assertValidType($type);

        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($type, $ruleName, $key);

        if (!$cache->has($banKey)) {
            return false;
        }

        $cache->delete($banKey);

        // Remove from registry
        $this->removeFromRegistry($type, $ruleName, $key);

        return true;
    }

    /**
     * List all currently banned keys for a rule.
     *
     * @return list<array{key: string, expiresAt: float}>
     */
    public function listBans(string $ruleName, string $type = 'allow2ban'): array
    {
        $this->assertValidType($type);

        $cache = $this->config->cache;
        $registry = $this->loadRegistry($type, $ruleName);
        $now = microtime(true);
        $active = [];
        $changed = false;

        foreach ($registry as $key => $expiresAt) {
            if ($expiresAt <= $now) {
                unset($registry[$key]);
                $changed = true;
                continue;
            }

            // Double-check the ban cache key still exists (cache may have evicted it)
            $banKey = $this->buildBanCacheKey($type, $ruleName, $key);
            if (!$cache->has($banKey)) {
                unset($registry[$key]);
                $changed = true;
                continue;
            }

            $active[] = ['key' => $key, 'expiresAt' => $expiresAt];
        }

        // Persist cleaned-up registry
        if ($changed) {
            $this->saveRegistry($type, $ruleName, $registry);
        }

        return $active;
    }

    /**
     * Clear all bans for a rule. Returns the number of bans cleared.
     */
    public function clearBans(string $ruleName, string $type = 'allow2ban'): int
    {
        $this->assertValidType($type);

        $cache = $this->config->cache;
        $registry = $this->loadRegistry($type, $ruleName);
        $now = microtime(true);
        $cleared = 0;

        foreach ($registry as $key => $expiresAt) {
            // Only count active (non-expired) bans
            if ($expiresAt <= $now) {
                continue;
            }

            $banKey = $this->buildBanCacheKey($type, $ruleName, $key);
            if ($cache->has($banKey)) {
                $cache->delete($banKey);
                ++$cleared;
            }
        }

        // Delete the registry itself
        $registryKey = self::registryKey($this->config->getKeyPrefix(), $type, $ruleName);
        $cache->delete($registryKey);

        return $cleared;
    }

    /**
     * List all rules that have active bans (across allow2ban and fail2ban).
     *
     * @return array{allow2ban: list<string>, fail2ban: list<string>}
     */
    public function listRulesWithBans(): array
    {
        $result = [
            'allow2ban' => [],
            'fail2ban' => [],
        ];

        // Check allow2ban rules
        foreach ($this->config->allow2ban->rules() as $fail2BanRule) {
            $bans = $this->listBans($fail2BanRule->name(), 'allow2ban');
            if ($bans !== []) {
                $result['allow2ban'][] = $fail2BanRule->name();
            }
        }

        // Check fail2ban rules
        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $bans = $this->listBans($fail2BanRule->name(), 'fail2ban');
            if ($bans !== []) {
                $result['fail2ban'][] = $fail2BanRule->name();
            }
        }

        return $result;
    }

    /**
     * Build the ban cache key for a given type, rule name, and key value.
     * Replicates the key generation logic from Firewall.
     */
    private function buildBanCacheKey(string $type, string $ruleName, string $key): string
    {
        $prefix = $this->config->getKeyPrefix();
        $safeName = self::normalizeKeyComponent($ruleName);
        $hashedKey = $this->hashKeyComponent($key);

        return match ($type) {
            'allow2ban' => $prefix . ':allow2ban:ban:' . $safeName . ':' . $hashedKey,
            'fail2ban' => $prefix . ':fail2ban:ban:' . $safeName . ':' . $hashedKey,
            default => throw new \InvalidArgumentException(sprintf('Invalid ban type "%s".', $type)),
        };
    }

    /**
     * Build the registry cache key.
     */
    private static function registryKey(string $prefix, string $type, string $ruleName): string
    {
        $safeName = self::normalizeKeyComponent($ruleName);

        return $prefix . ':ban-registry:' . $type . ':' . $safeName;
    }

    /**
     * Load the ban registry for a given type and rule name.
     *
     * @return array<string, float>
     */
    private function loadRegistry(string $type, string $ruleName): array
    {
        $cache = $this->config->cache;
        $registryKey = self::registryKey($this->config->getKeyPrefix(), $type, $ruleName);

        $raw = $cache->get($registryKey);
        if (!is_string($raw)) {
            return [];
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }

        /** @var array<string, float> $decoded */
        return $decoded;
    }

    /**
     * Save the ban registry for a given type and rule name.
     *
     * @param array<string, float> $registry
     */
    private function saveRegistry(string $type, string $ruleName, array $registry): void
    {
        $cache = $this->config->cache;
        $registryKey = self::registryKey($this->config->getKeyPrefix(), $type, $ruleName);

        if ($registry === []) {
            $cache->delete($registryKey);
            return;
        }

        $cache->set($registryKey, json_encode($registry, JSON_THROW_ON_ERROR));
    }

    /**
     * Remove a single key from the registry.
     */
    private function removeFromRegistry(string $type, string $ruleName, string $key): void
    {
        $registry = $this->loadRegistry($type, $ruleName);
        unset($registry[$key]);
        $this->saveRegistry($type, $ruleName, $registry);
    }

    /**
     * Validate that the type is one of the accepted values.
     */
    private function assertValidType(string $type): void
    {
        if (!in_array($type, self::VALID_TYPES, true)) {
            throw new \InvalidArgumentException(
                sprintf('Invalid ban type "%s". Expected one of: %s', $type, implode(', ', self::VALID_TYPES)),
            );
        }
    }

    /**
     * Normalize a key component for use in cache keys.
     * Replicates Firewall::normalizeKeyComponent().
     */
    private static function normalizeKeyComponent(string $value): string
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

    /**
     * Hash a key component for use in cache keys.
     * Replicates Firewall::hashKeyComponent().
     */
    private function hashKeyComponent(string $key): string
    {
        return hash('sha256', $key);
    }
}
