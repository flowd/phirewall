<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallTest extends TestCase
{
    public function testSafelistBypassesOtherRules(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->safelist('healthcheck', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklist('block-all', function ($request): bool {
            return true; // should be bypassed by safelist
        });

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/health');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
        $this->assertSame('healthcheck', $firewallResult->headers['X-Phirewall-Safelist'] ?? '');
    }

    public function testBlocklistBlocks(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/admin');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('blocklist', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('blockedPath', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottle429AndRetryAfter(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $period = 10;
        $limit = 2;
        $config->enableRateLimitHeaders();
        $config->throttle('ip', $limit, $period, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        $retryAfter = (int)($firewallResult->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retryAfter);
        $this->assertLessThanOrEqual($period, $retryAfter);

        // Rate limit headers should be consistent with the throttled state
        $this->assertSame((string)$limit, $firewallResult->headers['X-RateLimit-Limit'] ?? null);
        $this->assertSame('0', $firewallResult->headers['X-RateLimit-Remaining'] ?? null);
        $reset = (int)($firewallResult->headers['X-RateLimit-Reset'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $reset);
        $this->assertLessThanOrEqual($period, $reset);
    }

    public function testFail2BanBlocksAfterThreshold(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->fail2ban(
            'login',
            2,
            5,
            10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        // First failure
        $failedRequest = $serverRequest->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($failedRequest)->isPass());
        // Second failure -> reaches threshold and is already blocked
        $second = $firewall->decide($failedRequest);
        $this->assertTrue($second->isBlocked());
        // Third failure -> is above the threshold and is still blocked
        $third = $firewall->decide($failedRequest);
        $this->assertTrue($third->isBlocked());
        // Now even a normal request should be banned
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('fail2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottleWindowExpiresAndResetsCounter(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $period = 2; // short timeframe for testing
        $limit = 2;
        $config->enableRateLimitHeaders();
        $config->throttle('ip', $limit, $period, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '9.8.7.6']);

        // Fill the window
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);

        // Wait until the window has definitely expired
        sleep($period + 1);

        // After expiration the counter should start a new window
        $afterReset = $firewall->decide($serverRequest);
        $this->assertTrue($afterReset->isPass());
        // RateLimit headers should be set for the first request in the new window
        $this->assertArrayHasKey('X-RateLimit-Remaining', $afterReset->headers);
        $this->assertSame((string)($limit - 1), $afterReset->headers['X-RateLimit-Remaining']);
    }

    public function testFail2BanFailCounterExpiresBeforeThreshold(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $period = 2; // short window for fail counters
        $threshold = 2;
        $banSeconds = 5;

        $config->fail2ban(
            'login-reset',
            $threshold,
            $period,
            $banSeconds,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '4.3.2.1']);
        $failedRequest = $serverRequest->withHeader('X-Login-Failed', '1');

        // One failed attempt in the first window
        $this->assertTrue($firewall->decide($failedRequest)->isPass());

        // Let the window expire before issuing a second failure
        sleep($period + 1);

        // After expiration, counting should start again from 1 and not immediately ban
        $this->assertTrue($firewall->decide($failedRequest)->isPass());

        // Another normal request should still not be blocked
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
    }
}
