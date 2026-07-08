<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
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
        $config->enableResponseHeaders();

        $config->safelists->add('healthcheck', fn($request): bool => $request->getUri()->getPath() === '/health');
        $config->blocklists->add('block-all', function ($request): bool {
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
        $config->enableResponseHeaders();

        $config->blocklists->add('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');

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
        $config->throttles->add('ip', $limit, $period, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

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
        $config->enableResponseHeaders();

        $config->fail2ban->add(
            'login',
            2,
            5,
            10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'
        );
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);
        $failedRequest = $serverRequest->withHeader('X-Login-Failed', '1');
        // threshold=2 (>= semantic): every match is blocked, the 2nd match triggers the ban.
        $this->assertTrue($firewall->decide($failedRequest)->isBlocked());
        $second = $firewall->decide($failedRequest);
        $this->assertTrue($second->isBlocked());
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
        $config->throttles->add('ip', $limit, $period, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

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

    public function testFail2BanThresholdNRequestBansOnNthRequest(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableResponseHeaders();

        $blockedResponseInvocations = 0;
        $config->blocklistedResponseFactory = new Config\Response\ClosureBlocklistedResponseFactory(function (
            string $rule,
            string $type,
            \Psr\Http\Message\ServerRequestInterface $serverRequest,
        ) use (&$blockedResponseInvocations): \Psr\Http\Message\ResponseInterface {
            ++$blockedResponseInvocations;
            return new \Nyholm\Psr7\Response(403, ['X-Banned' => $rule], 'banned');
        });
        $config->fail2ban->add(
            'login',
            threshold: 3,
            period: 60,
            ban: 600,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $middleware = new \Flowd\Phirewall\Middleware($config, new \Nyholm\Psr7\Factory\Psr17Factory());

        $serverRequest = (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']))
            ->withHeader('X-Login-Failed', '1');
        $handler = new class () implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface
            {
                return new \Nyholm\Psr7\Response(200);
            }
        };

        // threshold=3: every match is blocked (403); the 3rd match is the banning one.
        // Each blocked match runs the blockedResponse factory.
        $firstResponse = $middleware->process($serverRequest, $handler);
        $this->assertSame(403, $firstResponse->getStatusCode(), '1st match must be blocked below the threshold');
        $this->assertSame('login', $firstResponse->getHeaderLine('X-Banned'));

        $secondResponse = $middleware->process($serverRequest, $handler);
        $this->assertSame(403, $secondResponse->getStatusCode(), '2nd match must be blocked below the threshold');

        $thirdResponse = $middleware->process($serverRequest, $handler);
        $this->assertSame(403, $thirdResponse->getStatusCode(), '3rd match must trigger the ban');
        $this->assertSame('login', $thirdResponse->getHeaderLine('X-Banned'));
        $this->assertSame(3, $blockedResponseInvocations, 'blockedResponse factory runs for every blocked match');
    }

    public function testFail2BanFailCounterExpiresBeforeThreshold(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $period = 2; // short window for fail counters
        $threshold = 2;
        $banSeconds = 5;

        $config->fail2ban->add(
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

        // One failed attempt in the first window: the match is blocked, but the key is not banned yet.
        $this->assertTrue($firewall->decide($failedRequest)->isBlocked());
        $this->assertFalse($firewall->isBanned('login-reset', '4.3.2.1', BanType::Fail2Ban));

        // Let the window expire before issuing a second failure
        sleep($period + 1);

        // After expiration, counting starts again from 1: still only a match, no ban.
        $this->assertTrue($firewall->decide($failedRequest)->isBlocked());
        $this->assertFalse($firewall->isBanned('login-reset', '4.3.2.1', BanType::Fail2Ban));

        // A clean (non-matching) request is not blocked because the key was never banned.
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
    }
}
