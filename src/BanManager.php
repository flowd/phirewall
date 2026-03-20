<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Psr\SimpleCache\CacheInterface;

final readonly class BanManager
{
    public function __construct(private Config $config)
    {
    }

    /**
     * Ban a key: set the ban cache key and register in the ban registry.
     *
     * @param string $ruleName The rule name
     * @param string $key The original (unhashed) key value (e.g. IP address)
     * @param int $banSeconds How long the ban lasts
     * @param BanType $banType The ban type
     */
    public function ban(string $ruleName, string $key, int $banSeconds, BanType $banType = BanType::Allow2Ban): void
    {
        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);

        $cache->set($banKey, 1, $banSeconds);

        $this->registerBan($cache, $banType, $ruleName, $key, microtime(true) + $banSeconds);
    }

    /**
     * Register a ban in the ban registry.
     *
     * @param CacheInterface $cache The cache store
     * @param BanType $banType The ban type
     * @param string $ruleName The rule name
     * @param string $key The original (unhashed) key value (e.g. IP address)
     * @param float $expiresAt microtime(true) + banSeconds
     */
    private function registerBan(
        CacheInterface $cache,
        BanType $banType,
        string $ruleName,
        string $key,
        float $expiresAt,
    ): void {
        $registryKey = $this->config->cacheKeyGenerator()->banRegistryKey($banType->value, $ruleName);

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
    public function isBanned(string $ruleName, string $key, BanType $banType = BanType::Allow2Ban): bool
    {
        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);

        return $cache->has($banKey);
    }

    /**
     * Unban a specific key for a rule. Returns true if the key was banned.
     */
    public function unban(string $ruleName, string $key, BanType $banType = BanType::Allow2Ban): bool
    {
        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);

        if (!$cache->has($banKey)) {
            return false;
        }

        $cache->delete($banKey);

        // Remove from registry
        $this->removeFromRegistry($banType, $ruleName, $key);

        return true;
    }

    /**
     * List all currently banned keys for a rule.
     *
     * @return list<array{key: string, expiresAt: float}>
     */
    public function listBans(string $ruleName, BanType $banType = BanType::Allow2Ban): array
    {
        $cache = $this->config->cache;
        $registry = $this->loadRegistry($banType, $ruleName);
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
            $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);
            if (!$cache->has($banKey)) {
                unset($registry[$key]);
                $changed = true;
                continue;
            }

            $active[] = ['key' => $key, 'expiresAt' => $expiresAt];
        }

        // Persist cleaned-up registry
        if ($changed) {
            $this->saveRegistry($banType, $ruleName, $registry);
        }

        return $active;
    }

    /**
     * Clear all bans for a rule. Returns the number of bans cleared.
     */
    public function clearBans(string $ruleName, BanType $banType = BanType::Allow2Ban): int
    {
        $cache = $this->config->cache;
        $registry = $this->loadRegistry($banType, $ruleName);
        $now = microtime(true);
        $cleared = 0;

        foreach ($registry as $key => $expiresAt) {
            // Only count active (non-expired) bans
            if ($expiresAt <= $now) {
                continue;
            }

            $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);
            if ($cache->has($banKey)) {
                $cache->delete($banKey);
                ++$cleared;
            }
        }

        // Delete the registry itself
        $registryKey = $this->config->cacheKeyGenerator()->banRegistryKey($banType->value, $ruleName);
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
            BanType::Allow2Ban->value => [],
            BanType::Fail2Ban->value => [],
        ];

        // Check allow2ban rules
        foreach ($this->config->allow2ban->rules() as $fail2BanRule) {
            $bans = $this->listBans($fail2BanRule->name(), BanType::Allow2Ban);
            if ($bans !== []) {
                $result[BanType::Allow2Ban->value][] = $fail2BanRule->name();
            }
        }

        // Check fail2ban rules
        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $bans = $this->listBans($fail2BanRule->name(), BanType::Fail2Ban);
            if ($bans !== []) {
                $result[BanType::Fail2Ban->value][] = $fail2BanRule->name();
            }
        }

        return $result;
    }

    /**
     * Build the ban cache key for a given type, rule name, and key value.
     */
    private function buildBanCacheKey(BanType $banType, string $ruleName, string $key): string
    {
        $cacheKeyGenerator = $this->config->cacheKeyGenerator();

        return match ($banType) {
            BanType::Allow2Ban => $cacheKeyGenerator->allow2BanBanKey($ruleName, $key),
            BanType::Fail2Ban => $cacheKeyGenerator->fail2BanBanKey($ruleName, $key),
        };
    }

    /**
     * Load the ban registry for a given type and rule name.
     *
     * @return array<string, float>
     */
    private function loadRegistry(BanType $banType, string $ruleName): array
    {
        $cache = $this->config->cache;
        $registryKey = $this->config->cacheKeyGenerator()->banRegistryKey($banType->value, $ruleName);

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
    private function saveRegistry(BanType $banType, string $ruleName, array $registry): void
    {
        $cache = $this->config->cache;
        $registryKey = $this->config->cacheKeyGenerator()->banRegistryKey($banType->value, $ruleName);

        if ($registry === []) {
            $cache->delete($registryKey);
            return;
        }

        $cache->set($registryKey, json_encode($registry, JSON_THROW_ON_ERROR));
    }

    /**
     * Remove a single key from the registry.
     */
    private function removeFromRegistry(BanType $banType, string $ruleName, string $key): void
    {
        $registry = $this->loadRegistry($banType, $ruleName);
        unset($registry[$key]);
        $this->saveRegistry($banType, $ruleName, $registry);
    }

}
