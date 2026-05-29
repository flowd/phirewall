<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

/**
 * Shared PSR-16 cache-key validation for the cache backends.
 *
 * PSR-16 (§1.1.1) requires a key to be a string of one or more characters and
 * reserves the characters {}()/\@: for future extensions; implementing libraries
 * MUST reject keys that contain them. As an additional restriction of its own
 * (not mandated by PSR-16), Phirewall also rejects control and whitespace
 * characters: they never appear in well-formed keys and almost always signal an
 * encoding bug in the caller.
 *
 * No upper length bound is enforced. PSR-16 only mandates that keys of at least
 * 64 characters be supported, so longer keys — such as a namespace prefix
 * followed by a 64-character sha256 fingerprint — remain valid.
 */
trait KeyValidationTrait
{
    /**
     * Validate a single cache key.
     *
     * @throws InvalidCacheKeyException When the key is empty, contains a reserved
     *                                  character, or contains a control or
     *                                  whitespace character.
     */
    private function validateKey(string $key): void
    {
        if ($key === '') {
            throw new InvalidCacheKeyException('Cache key must not be an empty string.');
        }

        // Report the offending character, never the raw key: a key may carry
        // attacker-influenced bytes (e.g. a header-derived discriminator), and
        // embedding control/newline characters into an exception message that
        // lands in a log is a log-injection vector (CWE-117). The rules live in
        // CacheKeyRules so they stay in sync with Config's key-prefix check.
        $illegalCharacter = CacheKeyRules::firstIllegalCharacter($key);
        if ($illegalCharacter !== null) {
            throw new InvalidCacheKeyException(CacheKeyRules::describeViolation('Cache key', $illegalCharacter));
        }
    }

    /**
     * Validate every entry of an iterable of keys, rejecting non-string entries
     * instead of silently casting them, and return them as a list of strings.
     *
     * @param iterable<mixed> $keys
     *
     * @return list<string>
     *
     * @throws InvalidCacheKeyException
     */
    private function validateKeyList(iterable $keys): array
    {
        $validatedKeys = [];
        foreach ($keys as $key) {
            $this->assertStringKey($key);
            $this->validateKey($key);
            $validatedKeys[] = $key;
        }

        return $validatedKeys;
    }

    /**
     * Validate the keys of a key/value iterable, rejecting non-string keys
     * instead of silently casting them, and return the pairs as an array.
     *
     * @param iterable<mixed, mixed> $values
     *
     * @return array<string, mixed>
     *
     * @throws InvalidCacheKeyException
     */
    private function validateKeyedValues(iterable $values): array
    {
        $validatedValues = [];
        foreach ($values as $key => $value) {
            $this->assertStringKey($key);
            $this->validateKey($key);
            $validatedValues[$key] = $value;
        }

        return $validatedValues;
    }

    /**
     * @phpstan-assert string $key
     *
     * @throws InvalidCacheKeyException When the key is not a string.
     */
    private function assertStringKey(mixed $key): void
    {
        if (!is_string($key)) {
            throw new InvalidCacheKeyException(sprintf(
                'Cache keys must be strings, %s given.',
                get_debug_type($key),
            ));
        }
    }
}
