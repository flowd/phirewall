<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Portable;

use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class PortableConfigTest extends TestCase
{
    public function testBlocklistPathEquals(): void
    {
        $portableConfig = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin')); // block /admin

        $config = $portableConfig->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());

        $result2 = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $result2->outcome);
        $this->assertSame('blocklist', $result2->headers['X-Phirewall'] ?? '');
        $this->assertSame('admin', $result2->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottleByIpAndRateLimitHeaders(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableRateLimitHeaders()
            ->throttle('ip', 1, 30, PortableConfig::keyIp());

        $config = $portableConfig->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('1', $firewallResult->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $firewallResult->headers['X-RateLimit-Remaining'] ?? '');

        $throttled = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $throttled->outcome);
        $this->assertSame('1', $throttled->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $throttled->headers['X-RateLimit-Remaining'] ?? '');
        $this->assertGreaterThanOrEqual(1, (int)($throttled->headers['X-RateLimit-Reset'] ?? '0'));
    }

    public function testFail2BanWithHeaderFilterAndIpKey(): void
    {
        $portableConfig = PortableConfig::create()
            ->fail2ban(
                'login',
                threshold: 2,
                period: 60,
                ban: 300,
                filter: PortableConfig::filterHeaderEquals('X-Login-Failed', '1'),
                key: PortableConfig::keyIp()
            );

        $config = $portableConfig->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $fail = $serverRequest->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($fail)->isPass());
        $this->assertTrue($firewall->decide($fail)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('fail2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testRoundTripExportImport(): void
    {
        $portableConfig = PortableConfig::create()
            ->setKeyPrefix('myapp')
            ->enableRateLimitHeaders()
            ->safelist('health', PortableConfig::filterPathEquals('/health'))
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->throttle('ip', 2, 10, PortableConfig::keyIp())
            ->track('login_failed', 60, PortableConfig::filterHeaderEquals('X-Login-Failed', '1'), PortableConfig::keyIp());

        $schema = $portableConfig->toArray();
        $json = json_encode($schema, JSON_THROW_ON_ERROR);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            $this->fail('Decoded data is not an array');
        }

        $portableConfig2 = PortableConfig::fromArray($data);

        $config = $portableConfig2->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        // Safelist
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('health', $firewallResult->headers['X-Phirewall-Safelist'] ?? '');
        // Blocklist
        $blocked = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
        // Throttle
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.77']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $tooMany = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $tooMany->outcome);
    }
}
