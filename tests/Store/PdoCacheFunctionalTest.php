<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Store;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\PdoCache;
use Nyholm\Psr7\ServerRequest;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Functional tests for PdoCache against real database backends.
 *
 * These tests run against whichever database is configured via the
 * PHIREWALL_PDO_DSN environment variable. When not set, SQLite in-memory
 * is used as fallback.
 *
 * In CI, the workflow matrix runs this suite once per database (SQLite, MySQL, PostgreSQL).
 */
#[\PHPUnit\Framework\Attributes\Group('database')]
final class PdoCacheFunctionalTest extends TestCase
{
    private string $dsn = 'sqlite::memory:';

    private ?string $user = null;

    private ?string $password = null;

    private string $tableName = 'phirewall_test';

    protected function setUp(): void
    {
        $this->dsn = getenv('PHIREWALL_PDO_DSN') ?: 'sqlite::memory:';
        $this->user = getenv('PHIREWALL_PDO_USER') ?: null;
        $this->password = getenv('PHIREWALL_PDO_PASSWORD') ?: null;

        // Unique table name per test to avoid cross-test pollution on shared databases.
        // For sqlite::memory: each createCache() gets its own connection and DB anyway.
        $this->tableName = 'phirewall_test_' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        // For shared databases (MySQL/PgSQL), clean up the test table.
        // For sqlite::memory:, the DB is gone when the connection closes — no cleanup needed.
        if (!str_contains($this->dsn, ':memory:')) {
            $pdo = new PDO($this->dsn, $this->user, $this->password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $driverName = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $quote = $driverName === 'mysql' ? '`' : '"';
            $pdo->exec(sprintf('DROP TABLE IF EXISTS %s%s%s', $quote, $this->tableName, $quote));
        }
    }

    /**
     * Each call creates a fresh PDO connection. For sqlite::memory: this means
     * an independent database, avoiding locking issues between cache operations.
     * For MySQL/PgSQL, the shared table name provides test isolation.
     */
    private function createCache(): PdoCache
    {
        $pdo = new PDO($this->dsn, $this->user, $this->password);
        return new PdoCache($pdo, $this->tableName);
    }

    // ── Basic CRUD ──────────────────────────────────────────────────────

    public function testSetAndGet(): void
    {
        $cache = $this->createCache();

        $cache->set('greeting', 'hello');
        $this->assertSame('hello', $cache->get('greeting'));
    }

    public function testGetMissingKeyReturnsDefault(): void
    {
        $cache = $this->createCache();

        $this->assertNull($cache->get('nonexistent'));
        $this->assertSame('fallback', $cache->get('nonexistent', 'fallback'));
    }

    public function testOverwriteExistingKey(): void
    {
        $cache = $this->createCache();

        $cache->set('key', 'first');
        $cache->set('key', 'second');
        $this->assertSame('second', $cache->get('key'));
    }

    public function testDelete(): void
    {
        $cache = $this->createCache();

        $cache->set('key', 'value');
        $this->assertTrue($cache->has('key'));

        $cache->delete('key');
        $this->assertFalse($cache->has('key'));
    }

    public function testClear(): void
    {
        $cache = $this->createCache();

        $cache->set('a', 1);
        $cache->set('b', 2);
        $cache->clear();

        $this->assertFalse($cache->has('a'));
        $this->assertFalse($cache->has('b'));
    }

    public function testHas(): void
    {
        $cache = $this->createCache();

        $this->assertFalse($cache->has('key'));
        $cache->set('key', 'value');
        $this->assertTrue($cache->has('key'));
    }

    // ── TTL ─────────────────────────────────────────────────────────────

    public function testSetWithTtl(): void
    {
        $cache = $this->createCache();

        $cache->set('key', 'value', 3600);
        $this->assertSame('value', $cache->get('key'));
        $this->assertGreaterThan(0, $cache->ttlRemaining('key'));
    }

    public function testTtlRemainingForMissingKey(): void
    {
        $cache = $this->createCache();

        $this->assertSame(0, $cache->ttlRemaining('missing'));
    }

    // ── Multiple operations ─────────────────────────────────────────────

    public function testGetMultiple(): void
    {
        $cache = $this->createCache();

        $cache->set('a', 'alpha');
        $cache->set('b', 'bravo');

        $result = $cache->getMultiple(['a', 'b', 'c'], 'default');
        $this->assertIsArray($result);

        $this->assertSame('alpha', $result['a']);
        $this->assertSame('bravo', $result['b']);
        $this->assertSame('default', $result['c']);
    }

    public function testSetMultiple(): void
    {
        $cache = $this->createCache();

        $cache->setMultiple(['x' => 10, 'y' => 20]);
        $this->assertSame(10, $cache->get('x'));
        $this->assertSame(20, $cache->get('y'));
    }

    public function testDeleteMultiple(): void
    {
        $cache = $this->createCache();

        $cache->set('a', 1);
        $cache->set('b', 2);
        $cache->set('c', 3);

        $cache->deleteMultiple(['a', 'c']);

        $this->assertFalse($cache->has('a'));
        $this->assertTrue($cache->has('b'));
        $this->assertFalse($cache->has('c'));
    }

    // ── Counter operations ──────────────────────────────────────────────

    public function testIncrementNewKey(): void
    {
        $cache = $this->createCache();

        $this->assertSame(1, $cache->increment('counter', 60));
    }

    public function testIncrementExistingKey(): void
    {
        $cache = $this->createCache();

        $cache->increment('counter', 60);
        $cache->increment('counter', 60);
        $this->assertSame(3, $cache->increment('counter', 60));
    }

    public function testIncrementSetsExpiry(): void
    {
        $cache = $this->createCache();

        $cache->increment('counter', 60);

        $ttl = $cache->ttlRemaining('counter');

        // Can be 0 if the clock ticks to a new window between increment() and ttlRemaining().
        $this->assertGreaterThanOrEqual(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);
    }

    public function testIncrementIndependentKeys(): void
    {
        $cache = $this->createCache();

        $cache->increment('a', 60);
        $cache->increment('a', 60);
        $cache->increment('b', 60);

        $this->assertSame(3, $cache->increment('a', 60));
        $this->assertSame(2, $cache->increment('b', 60));
    }

    // ── Complex value types ─────────────────────────────────────────────

    public function testStoresArrays(): void
    {
        $cache = $this->createCache();

        $data = ['count' => 5, 'expires_at' => 1700000000];
        $cache->set('structured', $data);
        $this->assertSame($data, $cache->get('structured'));
    }

    public function testStoresIntegers(): void
    {
        $cache = $this->createCache();

        $cache->set('number', 42);
        $this->assertSame(42, $cache->get('number'));
    }

    public function testStoresNullValue(): void
    {
        $cache = $this->createCache();

        $cache->set('nullable', null);
        $this->assertNull($cache->get('nullable'));
        $this->assertTrue($cache->has('nullable'));
    }

    // ── Firewall integration ────────────────────────────────────────────

    public function testWorksAsFirewallBackend(): void
    {
        $cache = $this->createCache();
        $config = new Config($cache);

        $config->throttle('api', limit: 3, period: 60, key: KeyExtractors::ip());

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertFalse($firewall->decide($request)->isPass());
    }

    public function testFail2BanWithRealDatabase(): void
    {
        $cache = $this->createCache();
        $config = new Config($cache);

        $config->fail2ban(
            'login',
            threshold: 2,
            period: 60,
            ban: 300,
            filter: fn($request): bool => $request->getHeaderLine('X-Failed') === '1',
            key: KeyExtractors::ip()
        );

        $firewall = new Firewall($config);
        $failedRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('X-Failed', '1');

        // First failure passes
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Second failure — reaches threshold, still allowed
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Third failure — exceeds threshold, triggers ban
        $this->assertFalse($firewall->decide($failedRequest)->isPass());
        // Clean request from same IP is now banned
        $cleanRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']);
        $this->assertFalse($firewall->decide($cleanRequest)->isPass());
    }
}
