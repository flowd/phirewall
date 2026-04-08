<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class ResetHelpersTest extends TestCase
{
    public function testResetThrottleAllowsRequestsAgain(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // Exhaust the throttle
        $firewall->decide($request);
        $firewall->decide($request);

        $result = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $result->outcome);

        // Reset and verify requests pass again
        $firewall->resetThrottle('ip', '1.2.3.4');
        $result = $firewall->decide($request);
        $this->assertTrue($result->isPass());
    }

    public function testResetFail2BanUnbansKey(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban->add(
            'login',
            2,
            60,
            300,
            fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        $failedRequest = $request->withHeader('X-Login-Failed', '1');

        // Trigger the ban (threshold=2 means 2 allowed, 3rd exceeds)
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);

        $result = $firewall->decide($request);
        $this->assertTrue($result->isBlocked());
        $this->assertTrue($firewall->isBanned('login', '5.6.7.8'));

        // Reset and verify the key is unbanned
        $firewall->resetFail2Ban('login', '5.6.7.8');
        $this->assertFalse($firewall->isBanned('login', '5.6.7.8'));
        $result = $firewall->decide($request);
        $this->assertTrue($result->isPass());
    }

    public function testIsBannedReturnsFalseWhenNotBanned(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban->add(
            'brute',
            3,
            60,
            300,
            fn($request): bool => true,
            fn($request): string => '10.0.0.1',
        );

        $firewall = new Firewall($config);
        $this->assertFalse($firewall->isBanned('brute', '10.0.0.1'));
    }

    public function testIsBannedSupportsBanTypeParameter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban->add(
            'brute',
            3,
            60,
            300,
            fn($request): bool => true,
            fn($request): string => '10.0.0.1',
        );

        $firewall = new Firewall($config);

        // Not banned for either type
        $this->assertFalse($firewall->isBanned('brute', '10.0.0.1', BanType::Fail2Ban));
        $this->assertFalse($firewall->isBanned('brute', '10.0.0.1', BanType::Allow2Ban));
    }

    public function testResetAllClearsEverything(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );
        $config->fail2ban->add(
            'login',
            2,
            60,
            300,
            fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);

        // Exhaust throttle
        $throttleRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $firewall->decide($throttleRequest);
        $firewall->decide($throttleRequest);

        $result = $firewall->decide($throttleRequest);
        $this->assertSame(Outcome::THROTTLED, $result->outcome);

        // Trigger fail2ban ban (threshold=2 means 2 allowed, 3rd exceeds)
        $banRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']))
            ->withHeader('X-Login-Failed', '1');
        $firewall->decide($banRequest);
        $firewall->decide($banRequest);
        $firewall->decide($banRequest);
        $this->assertTrue($firewall->isBanned('login', '5.6.7.8'));

        // Reset everything
        $firewall->resetAll();

        // Throttle should be cleared
        $result = $firewall->decide($throttleRequest);
        $this->assertTrue($result->isPass());

        // Ban should be cleared
        $this->assertFalse($firewall->isBanned('login', '5.6.7.8'));
    }

    public function testResetThrottleOnlyAffectsSpecificKey(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);
        $requestA = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.1.1.1']);
        $requestB = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2.2.2.2']);

        // Exhaust both
        $firewall->decide($requestA);
        $firewall->decide($requestA);
        $firewall->decide($requestA);

        $firewall->decide($requestB);
        $firewall->decide($requestB);
        $firewall->decide($requestB);

        // Reset only A
        $firewall->resetThrottle('ip', '1.1.1.1');

        // A should pass, B should still be throttled
        $this->assertTrue($firewall->decide($requestA)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($requestB)->outcome);
    }

    public function testResetFail2BanClearsFailCounterToo(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban->add(
            'login',
            3,
            60,
            300,
            fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);
        $failedRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']))
            ->withHeader('X-Login-Failed', '1');
        $normalRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '9.9.9.9']);

        // Accumulate 2 failures (below threshold of 3)
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);

        // Reset -- should clear the fail counter as well
        $firewall->resetFail2Ban('login', '9.9.9.9');

        // Now 2 more failures should not trigger a ban (counter was reset)
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);

        $result = $firewall->decide($normalRequest);
        $this->assertTrue($result->isPass(), 'Request should pass because fail counter was reset');
    }

    /**
     * Helper to create a Config with a deterministic clock for time-sensitive tests.
     */
    private function createConfigWithClock(): Config
    {
        $fakeClock = new FakeClock(1_200_000_000.0);
        $inMemoryCache = new InMemoryCache($fakeClock);

        return new Config($inMemoryCache, clock: $fakeClock);
    }

    public function testResetThrottleAppliesDiscriminatorNormalizer(): void
    {
        $config = $this->createConfigWithClock();
        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->throttles->add(
            'ip',
            2,
            60,
            fn($request): string => $request->getHeaderLine('X-User-Id'),
        );

        $firewall = new Firewall($config);
        $request = (new ServerRequest('GET', '/'))->withHeader('X-User-Id', 'USER_A');

        // Exhaust the throttle (normalized key: "user_a")
        $firewall->decide($request);
        $firewall->decide($request);

        $result = $firewall->decide($request);
        $this->assertSame(Outcome::THROTTLED, $result->outcome);

        // Reset using uppercase variant -- should normalize to "user_a" internally
        $firewall->resetThrottle('ip', 'USER_A');
        $result = $firewall->decide($request);
        $this->assertTrue($result->isPass(), 'Throttle should be reset after resetThrottle with normalized key');
    }

    public function testResetFail2BanAppliesDiscriminatorNormalizer(): void
    {
        $config = $this->createConfigWithClock();
        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->fail2ban->add(
            'login',
            2,
            60,
            300,
            fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            fn($request): string => $request->getHeaderLine('X-User-Id'),
        );

        $firewall = new Firewall($config);
        $failedRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-Login-Failed', '1')
            ->withHeader('X-User-Id', 'USER_A');

        // Trigger the ban (threshold=2 allows 2, 3rd exceeds; normalized key: "user_a")
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);

        $this->assertTrue($firewall->isBanned('login', 'USER_A'));

        // Reset using mixed-case variant -- should normalize internally
        $firewall->resetFail2Ban('login', 'User_A');
        $this->assertFalse($firewall->isBanned('login', 'user_a'));

        // Verify requests pass after reset
        $cleanRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-User-Id', 'USER_A');
        $result = $firewall->decide($cleanRequest);
        $this->assertTrue($result->isPass(), 'Request should pass after resetFail2Ban with normalized key');
    }

    public function testIsBannedAppliesDiscriminatorNormalizer(): void
    {
        $config = $this->createConfigWithClock();
        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->fail2ban->add(
            'login',
            2,
            60,
            300,
            fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            fn($request): string => $request->getHeaderLine('X-User-Id'),
        );

        $firewall = new Firewall($config);
        $failedRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-Login-Failed', '1')
            ->withHeader('X-User-Id', 'user_a');

        // Trigger the ban with lowercase variant (threshold=2 allows 2, 3rd exceeds)
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);
        $firewall->decide($failedRequest);

        // Check with uppercase -- should normalize and find the ban
        $this->assertTrue(
            $firewall->isBanned('login', 'USER_A'),
            'isBanned should find bans using normalized key regardless of input casing'
        );

        // Check with mixed-case
        $this->assertTrue(
            $firewall->isBanned('login', 'User_A'),
            'isBanned should find bans using normalized key regardless of input casing'
        );
    }
}
