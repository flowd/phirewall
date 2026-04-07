<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanManager;
use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class BanManagerTest extends TestCase
{
    private function makeRequest(string $ip = '1.2.3.4'): ServerRequest
    {
        return new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function makeFailedLoginRequest(string $ip = '5.6.7.8'): ServerRequest
    {
        return (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => $ip]))
            ->withHeader('X-Login-Failed', '1');
    }

    /**
     * Helper: configure allow2ban rule and return [Config, Firewall, BanManager].
     *
     * @return array{Config, Firewall, BanManager}
     */
    private function setupAllow2Ban(
        InMemoryCache $inMemoryCache,
        string $ruleName = 'test-rule',
        int $threshold = 3,
        int $period = 60,
        int $banSeconds = 3600,
    ): array {
        $config = new Config($inMemoryCache);
        $config->allow2ban->add(
            $ruleName,
            threshold: $threshold,
            period: $period,
            banSeconds: $banSeconds,
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $banManager = $config->banManager();

        return [$config, $firewall, $banManager];
    }

    /**
     * Helper: configure fail2ban rule and return [Config, Firewall, BanManager].
     *
     * @return array{Config, Firewall, BanManager}
     */
    private function setupFail2Ban(
        InMemoryCache $inMemoryCache,
        string $ruleName = 'login-rule',
        int $threshold = 2,
        int $period = 60,
        int $banSeconds = 3600,
    ): array {
        $config = new Config($inMemoryCache);
        $config->fail2ban->add(
            $ruleName,
            threshold: $threshold,
            period: $period,
            ban: $banSeconds,
            filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $banManager = $config->banManager();

        return [$config, $firewall, $banManager];
    }

    /**
     * Trigger an allow2ban ban by sending enough requests to exceed the threshold.
     */
    private function triggerAllow2Ban(Firewall $firewall, string $ip, int $threshold): void
    {
        $serverRequest = $this->makeRequest($ip);
        for ($i = 0; $i <= $threshold; ++$i) {
            $firewall->decide($serverRequest);
        }
    }

    /**
     * Trigger a fail2ban ban by sending enough failed requests to exceed the threshold.
     */
    private function triggerFail2Ban(Firewall $firewall, string $ip, int $threshold): void
    {
        $serverRequest = $this->makeFailedLoginRequest($ip);
        for ($i = 0; $i <= $threshold; ++$i) {
            $firewall->decide($serverRequest);
        }
    }

    // ── Test 1: isBanned returns false when not banned ──────────────────

    public function testIsBannedReturnsFalseWhenNotBanned(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, , $banManager] = $this->setupAllow2Ban($inMemoryCache);

        $this->assertFalse(
            $banManager->isBanned('test-rule', '1.2.3.4'),
            'A key that has never been seen should not be reported as banned',
        );
    }

    // ── Test 2: isBanned returns true after allow2ban triggered ─────────

    public function testIsBannedReturnsTrueAfterAllow2BanTriggered(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3);

        $this->triggerAllow2Ban($firewall, '1.2.3.4', 3);

        // Verify the firewall itself blocks
        $firewallResult = $firewall->decide($this->makeRequest('1.2.3.4'));
        $this->assertTrue($firewallResult->isBlocked(), 'Firewall should block after threshold');

        // BanManager should report the same
        $this->assertTrue(
            $banManager->isBanned('test-rule', '1.2.3.4'),
            'isBanned should return true for a banned allow2ban key',
        );
    }

    // ── Test 3: isBanned returns true after fail2ban triggered ──────────

    public function testIsBannedReturnsTrueAfterFail2BanTriggered(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupFail2Ban($inMemoryCache, threshold: 2);

        $this->triggerFail2Ban($firewall, '5.6.7.8', 2);

        // Verify the firewall blocks even a normal request from the banned IP
        $serverRequest = $this->makeRequest('5.6.7.8');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked(), 'Firewall should block after fail2ban threshold');

        // BanManager should report the ban with type='fail2ban'
        $this->assertTrue(
            $banManager->isBanned('login-rule', '5.6.7.8', BanType::Fail2Ban),
            'isBanned should return true for a banned fail2ban key',
        );
    }

    // ── Test 4: unban removes a ban ─────────────────────────────────────

    public function testUnbanRemovesBan(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3);

        $this->triggerAllow2Ban($firewall, '1.2.3.4', 3);

        // Verify banned
        $this->assertTrue($banManager->isBanned('test-rule', '1.2.3.4'));
        $this->assertTrue(
            $firewall->decide($this->makeRequest('1.2.3.4'))->isBlocked(),
            'Should be blocked before unban',
        );

        // Unban
        $result = $banManager->unban('test-rule', '1.2.3.4');
        $this->assertTrue($result, 'unban should return true when a ban was removed');

        // Verify no longer banned
        $this->assertFalse(
            $banManager->isBanned('test-rule', '1.2.3.4'),
            'isBanned should return false after unban',
        );

        // Verify requests pass again through the firewall
        $this->assertTrue(
            $firewall->decide($this->makeRequest('1.2.3.4'))->isPass(),
            'Requests should pass after unban',
        );
    }

    // ── Test 5: unban returns false when not banned ─────────────────────

    public function testUnbanReturnsFalseWhenNotBanned(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, , $banManager] = $this->setupAllow2Ban($inMemoryCache);

        $result = $banManager->unban('test-rule', '99.99.99.99');
        $this->assertFalse($result, 'unban should return false when key is not banned');
    }

    // ── Test 6: listBans returns active bans ────────────────────────────

    public function testListBansReturnsActiveBans(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3, banSeconds: 3600);

        $ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
        foreach ($ips as $ip) {
            $this->triggerAllow2Ban($firewall, $ip, 3);
        }

        $bans = $banManager->listBans('test-rule');

        $this->assertCount(3, $bans, 'Should list 3 active bans');

        // Extract the keys from the ban list
        $bannedKeys = array_column($bans, 'key');
        foreach ($ips as $ip) {
            $this->assertContains($ip, $bannedKeys, sprintf('IP %s should appear in ban list', $ip));
        }

        // Each entry should have an expiresAt field
        foreach ($bans as $ban) {
            $this->assertArrayHasKey('key', $ban);
            $this->assertArrayHasKey('expiresAt', $ban);
            $this->assertIsFloat($ban['expiresAt']);
            $this->assertGreaterThan($fakeClock->now(), $ban['expiresAt'], 'expiresAt should be in the future');
        }
    }

    // ── Test 7: listBans filters expired bans ───────────────────────────

    public function testListBansFiltersExpiredBans(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3, banSeconds: 3600);

        $this->triggerAllow2Ban($firewall, '10.0.0.1', 3);
        $this->triggerAllow2Ban($firewall, '10.0.0.2', 3);

        // Verify bans exist before time advancement
        $bans = $banManager->listBans('test-rule');
        $this->assertCount(2, $bans, 'Should have 2 bans before expiry');

        // Advance time past the ban duration
        $fakeClock->advance(3601);

        // After expiry, listBans should return empty
        $bans = $banManager->listBans('test-rule');
        $this->assertCount(0, $bans, 'Should have 0 bans after expiry');
    }

    // ── Test 8: clearBans removes all bans ──────────────────────────────

    public function testClearBansRemovesAllBans(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3, banSeconds: 3600);

        $ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
        foreach ($ips as $ip) {
            $this->triggerAllow2Ban($firewall, $ip, 3);
        }

        // Verify all are banned
        foreach ($ips as $ip) {
            $this->assertTrue($banManager->isBanned('test-rule', $ip), sprintf('IP %s should be banned', $ip));
        }

        // Clear all bans
        $clearedCount = $banManager->clearBans('test-rule');
        $this->assertSame(3, $clearedCount, 'clearBans should return the number of bans cleared');

        // Verify all IPs can request again
        foreach ($ips as $ip) {
            $this->assertFalse(
                $banManager->isBanned('test-rule', $ip),
                sprintf('IP %s should not be banned after clearBans', $ip),
            );
            $this->assertTrue(
                $firewall->decide($this->makeRequest($ip))->isPass(),
                sprintf('IP %s should pass through firewall after clearBans', $ip),
            );
        }
    }

    // ── Test 9: listRulesWithBans ───────────────────────────────────────

    public function testListRulesWithBans(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);

        // Two allow2ban rules
        $config->allow2ban->add(
            'api-rate',
            threshold: 3,
            period: 60,
            banSeconds: 3600,
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );
        $config->allow2ban->add(
            'page-rate',
            threshold: 5,
            period: 60,
            banSeconds: 1800,
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );

        // One fail2ban rule
        $config->fail2ban->add(
            'login-abuse',
            threshold: 2,
            period: 60,
            ban: 3600,
            filter: fn($req): bool => $req->getHeaderLine('X-Login-Failed') === '1',
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $banManager = $config->banManager();

        // Trigger ban on 'api-rate' (allow2ban)
        $this->triggerAllow2Ban($firewall, '10.0.0.1', 3);

        // Trigger ban on 'page-rate' (allow2ban, threshold=5 allows 5, 6th triggers ban)
        for ($i = 0; $i < 6; ++$i) {
            $firewall->decide($this->makeRequest('10.0.0.2'));
        }

        // Trigger ban on 'login-abuse' (fail2ban)
        $this->triggerFail2Ban($firewall, '10.0.0.3', 2);

        $rulesWithBans = $banManager->listRulesWithBans();

        // Verify structure
        $this->assertArrayHasKey('allow2ban', $rulesWithBans);
        $this->assertArrayHasKey('fail2ban', $rulesWithBans);

        // Verify allow2ban rules
        $this->assertContains('api-rate', $rulesWithBans['allow2ban']);
        $this->assertContains('page-rate', $rulesWithBans['allow2ban']);

        // Verify fail2ban rules
        $this->assertContains('login-abuse', $rulesWithBans['fail2ban']);
    }

    // ── Test 10: unban does not affect other keys ───────────────────────

    public function testUnbanDoesNotAffectOtherKeys(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupAllow2Ban($inMemoryCache, threshold: 3, banSeconds: 3600);

        // Ban two IPs
        $this->triggerAllow2Ban($firewall, '10.0.0.1', 3);
        $this->triggerAllow2Ban($firewall, '10.0.0.2', 3);

        // Verify both are banned
        $this->assertTrue($banManager->isBanned('test-rule', '10.0.0.1'));
        $this->assertTrue($banManager->isBanned('test-rule', '10.0.0.2'));

        // Unban only the first IP
        $banManager->unban('test-rule', '10.0.0.1');

        // First IP should no longer be banned
        $this->assertFalse(
            $banManager->isBanned('test-rule', '10.0.0.1'),
            'Unbanned IP should not be reported as banned',
        );
        $this->assertTrue(
            $firewall->decide($this->makeRequest('10.0.0.1'))->isPass(),
            'Unbanned IP should pass through firewall',
        );

        // Second IP should still be banned
        $this->assertTrue(
            $banManager->isBanned('test-rule', '10.0.0.2'),
            'Other IP should remain banned',
        );
        $this->assertTrue(
            $firewall->decide($this->makeRequest('10.0.0.2'))->isBlocked(),
            'Other IP should remain blocked by firewall',
        );
    }

    // ── Additional edge case: unban with fail2ban type ──────────────────

    public function testUnbanRemovesFail2Ban(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, $firewall, $banManager] = $this->setupFail2Ban($inMemoryCache, threshold: 2, banSeconds: 3600);

        $this->triggerFail2Ban($firewall, '5.6.7.8', 2);

        // Verify banned
        $this->assertTrue($banManager->isBanned('login-rule', '5.6.7.8', BanType::Fail2Ban));

        // Unban
        $result = $banManager->unban('login-rule', '5.6.7.8', BanType::Fail2Ban);
        $this->assertTrue($result, 'unban should return true for fail2ban ban removal');

        // Verify no longer banned
        $this->assertFalse($banManager->isBanned('login-rule', '5.6.7.8', BanType::Fail2Ban));

        // Normal requests should pass again
        $this->assertTrue(
            $firewall->decide($this->makeRequest('5.6.7.8'))->isPass(),
            'Requests should pass after fail2ban unban',
        );
    }

    // ── Additional edge case: clearBans returns 0 when no bans exist ───

    public function testClearBansReturnsZeroWhenNoBansExist(): void
    {
        $inMemoryCache = new InMemoryCache();
        [, , $banManager] = $this->setupAllow2Ban($inMemoryCache);

        $clearedCount = $banManager->clearBans('test-rule');
        $this->assertSame(0, $clearedCount, 'clearBans should return 0 when no bans exist');
    }

    // ── Additional edge case: listRulesWithBans empty when no bans ─────

    public function testListRulesWithBansReturnsEmptyWhenNoBans(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->allow2ban->add(
            'unused-rule',
            threshold: 10,
            period: 60,
            banSeconds: 3600,
            key: fn($req): string => $req->getServerParams()['REMOTE_ADDR'],
        );

        $banManager = $config->banManager();
        $rulesWithBans = $banManager->listRulesWithBans();

        // Should return empty arrays for both types (or empty overall)
        $allow2banRules = $rulesWithBans['allow2ban'] ?? [];
        $fail2banRules = $rulesWithBans['fail2ban'] ?? [];

        $this->assertEmpty($allow2banRules, 'No allow2ban rules should have active bans');
        $this->assertEmpty($fail2banRules, 'No fail2ban rules should have active bans');
    }

}
