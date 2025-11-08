<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RateLimitHeadersTest extends TestCase
{
    public function testHeadersPresentWhenEnabledAndNotExceeded(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableRateLimitHeaders(true);
        // Limit 3 requests per 30s by IP
        $config->throttle('ip', 3, 30, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.1.1.1']);
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());

        $limit = $firewallResult->headers['X-RateLimit-Limit'] ?? '';
        $remaining = $firewallResult->headers['X-RateLimit-Remaining'] ?? '';
        $reset = $firewallResult->headers['X-RateLimit-Reset'] ?? '';
        $this->assertSame('3', $limit);
        $this->assertSame('2', $remaining);
        $this->assertGreaterThanOrEqual(1, (int)$reset);
    }

    public function testHeadersPresentWhenExceededAndMatchRetryAfter(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableRateLimitHeaders(true);
        // Limit 1 per 10s by IP
        $config->throttle('ip', 1, 10, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2.2.2.2']);
        // First ok
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        // Second should be throttled
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertSame('1', $firewallResult->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $firewallResult->headers['X-RateLimit-Remaining'] ?? '');
        $reset = (int)($firewallResult->headers['X-RateLimit-Reset'] ?? '0');
        $retry = (int)($firewallResult->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertSame($retry, $reset, 'Reset should match Retry-After when throttled');
    }

    public function testHeadersAbsentWhenDisabled(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableRateLimitHeaders(false);
        $config->throttle('ip', 10, 60, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);

        $firewall = new Firewall($config);

        $firewallResult = $firewall->decide(new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '3.3.3.3']));
        $this->assertSame('', $firewallResult->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('', $firewallResult->headers['X-RateLimit-Remaining'] ?? '');
        $this->assertSame('', $firewallResult->headers['X-RateLimit-Reset'] ?? '');
    }
}
