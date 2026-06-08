<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\CacheKeyGenerator;
use Flowd\Phirewall\Store\CacheKeyRules;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Store\InvalidCacheKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Regression guard: every cache key produced by {@see CacheKeyGenerator} must
 * satisfy the PSR-16 key rules enforced by the cache backends, so the two can
 * never drift apart. A rule name may legitimately contain reserved characters
 * (e.g. a dynamic-period rule name like "api:p60"); normalizeName() must strip
 * them before the value becomes part of a cache key.
 */
#[CoversClass(CacheKeyGenerator::class)]
final class CacheKeyGeneratorTest extends TestCase
{
    /**
     * Rule names that must all survive normalisation as valid key fragments.
     *
     * @return iterable<array{0: string}>
     */
    public static function ruleNames(): iterable
    {
        yield ['simple'];
        yield ['api:p60'];                // dynamic-period rule name (contains a colon)
        yield ['api:60s'];                // multiThrottle sub-rule name
        yield ['rule with spaces'];
        yield ['rule/with\\slashes'];
        yield ['weird{}()@:name'];
        yield ['café-ünïcode'];
        yield ['UPPER.lower_0-9'];
        yield [str_repeat('x', 300)];     // very long: truncated + hashed
        yield ['   '];                    // whitespace only
        yield [''];                       // empty
    }

    /**
     * @return list<string> Every key the generator can produce for a name/key pair.
     */
    private function allKeysFor(CacheKeyGenerator $generator, string $name, string $userKey): array
    {
        return [
            $generator->throttleKey($name, $userKey),
            $generator->slidingWindowKey($name, $userKey, 0),
            $generator->slidingWindowKey($name, $userKey, 1_716_998_400),
            $generator->fail2BanFailKey($name, $userKey),
            $generator->fail2BanBanKey($name, $userKey),
            $generator->allow2BanHitKey($name, $userKey),
            $generator->allow2BanBanKey($name, $userKey),
            $generator->trackKey($name, $userKey),
            $generator->banRegistryKey(BanType::Fail2Ban->value, $name),
            $generator->banRegistryKey(BanType::Allow2Ban->value, $name),
        ];
    }

    #[DataProvider('ruleNames')]
    public function testGeneratedKeysContainNoReservedOrControlCharacters(string $name): void
    {
        $generator = new CacheKeyGenerator('phirewall');

        foreach (['203.0.113.7', 'token:with:colons', "ua\twith\nwhitespace", ''] as $userKey) {
            foreach ($this->allKeysFor($generator, $name, $userKey) as $key) {
                $this->assertFalse(
                    strpbrk($key, CacheKeyRules::RESERVED_CHARACTERS),
                    sprintf('Generated key "%s" contains a reserved character.', $key),
                );
                $this->assertDoesNotMatchRegularExpression(
                    '/[\s\x00-\x1f\x7f]/',
                    $key,
                    sprintf('Generated key "%s" contains a control or whitespace character.', $key),
                );
            }
        }
    }

    public function testLongRuleNameIsTruncatedToTheBudgetWithAHashSuffix(): void
    {
        $generator = new CacheKeyGenerator('phirewall');

        $normalized = $generator->normalizeName(str_repeat('x', 300));

        // The constants MAX_NAME_LENGTH (120) and HASH_SUFFIX_LENGTH (12) must
        // not drift: a truncated name is exactly the budget length and ends in
        // a '-' separator followed by a 12-char lowercase-hex sha1 fragment.
        $this->assertSame(120, strlen($normalized));
        $this->assertMatchesRegularExpression('/^x{107}-[0-9a-f]{12}$/', $normalized);
    }

    public function testRuleNameAtTheBudgetLengthIsNotTruncated(): void
    {
        $generator = new CacheKeyGenerator('phirewall');

        $name = str_repeat('x', 120);

        $this->assertSame($name, $generator->normalizeName($name));
    }

    #[DataProvider('ruleNames')]
    public function testGeneratedKeysAreAcceptedByTheCacheBackend(string $name): void
    {
        $generator = new CacheKeyGenerator('phirewall');
        $cache = new InMemoryCache();

        foreach (['203.0.113.7', 'token:with:colons', ''] as $userKey) {
            foreach ($this->allKeysFor($generator, $name, $userKey) as $key) {
                try {
                    $this->assertTrue($cache->set($key, true));
                    $this->assertTrue($cache->get($key));
                } catch (InvalidCacheKeyException $exception) {
                    $this->fail(sprintf(
                        'Generated key "%s" was rejected by the cache backend: %s',
                        $key,
                        $exception->getMessage(),
                    ));
                }
            }
        }
    }
}
