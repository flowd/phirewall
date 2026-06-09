<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

final readonly class BanManager
{
    public function __construct(private Config $config)
    {
    }

    /**
     * Ban a key.
     *
     * Two writes happen:
     *   - The primary ban cache key is the source of truth checked by
     *     {@see isBanned()}. It is set atomically and is not affected by
     *     contention on the audit registry below.
     *   - The audit registry backs {@see listBans()} and
     *     {@see listRulesWithBans()}. It is best-effort: two concurrent
     *     ban() calls for the same rule may cause one of the entries to
     *     lose to the other and only appear after the next save reconciles.
     *
     * @param string $ruleName The rule name
     * @param string $key The original (unhashed) key value (e.g. IP address)
     * @param int $banSeconds How long the ban lasts
     * @param BanType $banType Which ban category the entry belongs to
     */
    public function ban(string $ruleName, string $key, int $banSeconds, BanType $banType = BanType::Allow2Ban): void
    {
        $cache = $this->config->cache;
        $banKey = $this->buildBanCacheKey($banType, $ruleName, $key);

        $cache->set($banKey, 1, $banSeconds);

        $registry = $this->loadRegistry($banType, $ruleName);
        $registry[$key] = $this->config->now() + $banSeconds;
        $this->saveRegistry($banType, $ruleName, $registry);
    }

    /**
     * Check if a specific key is currently banned for a rule.
     *
     * The ban category must be passed explicitly. This method and
     * {@see Http\Firewall::isBanned()} previously carried
     * conflicting defaults, so a caller that reached for the wrong entry point
     * silently queried the other category (an allow2ban and a fail2ban entry for
     * the same rule and key live under distinct cache keys) and got a false
     * negative. The default is therefore removed from both isBanned() methods.
     */
    public function isBanned(string $ruleName, string $key, BanType $banType): bool
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

        $registry = $this->loadRegistry($banType, $ruleName);
        unset($registry[$key]);
        $this->saveRegistry($banType, $ruleName, $registry);

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
        $now = $this->config->now();
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
        $now = $this->config->now();
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
        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $bans = $this->listBans($allow2BanRule->name(), BanType::Allow2Ban);
            if ($bans !== []) {
                $result[BanType::Allow2Ban->value][] = $allow2BanRule->name();
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

        // The registry is stored as a native array. A string is a legacy/foreign payload (or a
        // backend that returns JSON verbatim) and is decoded here; a backend that already decodes
        // JSON documents (e.g. RedisCache) returns the array directly.
        if (is_string($raw)) {
            try {
                $raw = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return [];
            }
        }

        if (!is_array($raw)) {
            return [];
        }

        // Coerce defensively: an older format, a tampered cache entry, or a foreign producer could
        // put non-numeric or non-finite values here. A non-finite expiry (e.g. "1e400" casting to
        // INF) would also make a JSON-encoding backend throw on the next save, so drop it here too.
        $registry = [];
        foreach ($raw as $key => $expiresAt) {
            if (is_string($key) && is_numeric($expiresAt) && is_finite((float) $expiresAt)) {
                $registry[$key] = (float) $expiresAt;
            }
        }

        return $registry;
    }

    /**
     * Save the ban registry for a given type and rule name.
     *
     * Prunes expired entries before saving and applies a TTL matching the
     * longest-surviving entry so the registry cannot grow without bound
     * under ban churn.
     *
     * @param array<string, float> $registry
     */
    private function saveRegistry(BanType $banType, string $ruleName, array $registry): void
    {
        $cache = $this->config->cache;
        $registryKey = $this->config->cacheKeyGenerator()->banRegistryKey($banType->value, $ruleName);

        $now = $this->config->now();
        $registry = array_filter($registry, static fn(float $expiresAt): bool => $expiresAt > $now);

        if ($registry === []) {
            $cache->delete($registryKey);
            return;
        }

        // TTL matches the longest-surviving ban's remaining lifetime so the
        // registry cache entry expires together with the last ban it tracks.
        $ttl = (int) max(1, ceil(max($registry) - $now));

        // Store as a native array so every backend's own serialization round-trips it. Pre-encoding
        // to a JSON string here was the previous bug: a backend that decodes JSON documents on read
        // (e.g. RedisCache) returned an array, which loadRegistry then rejected as a non-string.
        $cache->set($registryKey, $registry, $ttl);
    }
}
