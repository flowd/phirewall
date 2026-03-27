<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the opt-in response header toggle (enableResponseHeaders).
 *
 * X-Phirewall, X-Phirewall-Matched, and X-Phirewall-Safelist headers are only
 * included in FirewallResult when explicitly enabled via $config->enableResponseHeaders().
 * Retry-After and X-RateLimit-* headers are NOT affected by this toggle.
 */
final class ResponseHeaderToggleTest extends TestCase
{
    public function testBlockedResponseOmitsPhirewallHeadersByDefault(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklist('block-all', fn($request): bool => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertArrayNotHasKey('X-Phirewall', $firewallResult->headers);
        $this->assertArrayNotHasKey('X-Phirewall-Matched', $firewallResult->headers);
    }

    public function testBlockedResponseIncludesPhirewallHeadersWhenEnabled(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableResponseHeaders();
        $config->blocklist('block-all', fn($request): bool => true);

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('blocklist', $firewallResult->headers['X-Phirewall']);
        $this->assertSame('block-all', $firewallResult->headers['X-Phirewall-Matched']);
    }

    public function testThrottledResponseAlwaysIncludesRetryAfter(): void
    {
        $config = new Config(new InMemoryCache());
        // Do NOT enable response headers — Retry-After must still be present
        $config->throttle('ip', 0, 30, fn($request): string => '1.2.3.4');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
        $this->assertArrayHasKey('Retry-After', $firewallResult->headers);
        $this->assertGreaterThanOrEqual(1, (int) $firewallResult->headers['Retry-After']);
        $this->assertArrayNotHasKey('X-Phirewall', $firewallResult->headers);
        $this->assertArrayNotHasKey('X-Phirewall-Matched', $firewallResult->headers);
    }

    public function testSafelistResponseOmitsSafelistHeaderByDefault(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelist('health', fn($request): bool => $request->getUri()->getPath() === '/health');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));

        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
        $this->assertArrayNotHasKey('X-Phirewall-Safelist', $firewallResult->headers);
    }

    public function testSafelistResponseIncludesSafelistHeaderWhenEnabled(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableResponseHeaders();
        $config->safelist('health', fn($request): bool => $request->getUri()->getPath() === '/health');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));

        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
        $this->assertSame('health', $firewallResult->headers['X-Phirewall-Safelist']);
    }

    public function testAllow2banResponseOmitsPhirewallHeadersByDefaultButIncludesRetryAfter(): void
    {
        $config = new Config(new InMemoryCache());
        // Do NOT enable response headers — Retry-After must still be present
        $config->allow2ban->add('ip', threshold: 1, period: 30, banSeconds: 60, key: fn($request): string => '1.2.3.4');

        $firewall = new Firewall($config);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertArrayHasKey('Retry-After', $firewallResult->headers);
        $this->assertGreaterThanOrEqual(1, (int) $firewallResult->headers['Retry-After']);
        $this->assertArrayNotHasKey('X-Phirewall', $firewallResult->headers);
        $this->assertArrayNotHasKey('X-Phirewall-Matched', $firewallResult->headers);
    }

    public function testRateLimitHeadersUnaffectedByResponseHeaderToggle(): void
    {
        $config = new Config(new InMemoryCache());
        // Enable rate limit headers but NOT response headers
        $config->enableRateLimitHeaders();
        $config->throttle('ip', 2, 60, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // First request passes — rate limit headers should be present
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('2', $firewallResult->headers['X-RateLimit-Limit']);
        $this->assertSame('1', $firewallResult->headers['X-RateLimit-Remaining']);
        $this->assertArrayHasKey('X-RateLimit-Reset', $firewallResult->headers);

        // Exhaust the limit
        $firewall->decide($serverRequest);
        $throttled = $firewall->decide($serverRequest);

        $this->assertSame(Outcome::THROTTLED, $throttled->outcome);
        $this->assertSame('2', $throttled->headers['X-RateLimit-Limit']);
        $this->assertSame('0', $throttled->headers['X-RateLimit-Remaining']);
        $this->assertArrayHasKey('Retry-After', $throttled->headers);
        // X-Phirewall headers should NOT be present (response headers not enabled)
        $this->assertArrayNotHasKey('X-Phirewall', $throttled->headers);
        $this->assertArrayNotHasKey('X-Phirewall-Matched', $throttled->headers);
    }
}
