<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RateLimitHeadersTest extends TestCase
{
    public function testHeadersPresentWhenEnabledAndNotExceeded(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(true);
        // Limit 3 requests per 30s by IP
        $config->throttle('ip', 3, 30, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.1.1.1']);
        $result = $firewall->decide($request);
        $this->assertTrue($result->isPass());

        $limit = $result->headers['X-RateLimit-Limit'] ?? '';
        $remaining = $result->headers['X-RateLimit-Remaining'] ?? '';
        $reset = $result->headers['X-RateLimit-Reset'] ?? '';
        $this->assertSame('3', $limit);
        $this->assertSame('2', $remaining);
        $this->assertGreaterThanOrEqual(1, (int)$reset);
    }

    public function testHeadersPresentWhenExceededAndMatchRetryAfter(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(true);
        // Limit 1 per 10s by IP
        $config->throttle('ip', 1, 10, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $firewall = new Firewall($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '2.2.2.2']);
        // First ok
        $this->assertTrue($firewall->decide($request)->isPass());
        // Second should be throttled
        $result = $firewall->decide($request);
        $this->assertSame(FirewallResult::OUTCOME_THROTTLED, $result->outcome);
        $this->assertSame('1', $result->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $result->headers['X-RateLimit-Remaining'] ?? '');
        $reset = (int)($result->headers['X-RateLimit-Reset'] ?? '0');
        $retry = (int)($result->headers['Retry-After'] ?? '0');
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertSame($retry, $reset, 'Reset should match Retry-After when throttled');
    }

    public function testHeadersAbsentWhenDisabled(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->enableRateLimitHeaders(false);
        $config->throttle('ip', 10, 60, fn($req): ?string => $req->getServerParams()['REMOTE_ADDR'] ?? null);
        $firewall = new Firewall($config);

        $result = $firewall->decide(new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '3.3.3.3']));
        $this->assertSame('', $result->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('', $result->headers['X-RateLimit-Remaining'] ?? '');
        $this->assertSame('', $result->headers['X-RateLimit-Reset'] ?? '');
    }
}
