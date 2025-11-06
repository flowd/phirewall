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

        $result1 = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($result1->isPass());

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

        $req = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
        $ok = $firewall->decide($req);
        $this->assertTrue($ok->isPass());
        $this->assertSame('1', $ok->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $ok->headers['X-RateLimit-Remaining'] ?? '');

        $throttled = $firewall->decide($req);
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

        $r = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $fail = $r->withHeader('X-Login-Failed', '1');
        $this->assertTrue($firewall->decide($fail)->isPass());
        $this->assertTrue($firewall->decide($fail)->isPass());
        $b = $firewall->decide($r);
        $this->assertSame(Outcome::BLOCKED, $b->outcome);
        $this->assertSame('fail2ban', $b->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $b->headers['X-Phirewall-Matched'] ?? '');
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
        $portableConfig2 = PortableConfig::fromArray($data);

        $config = $portableConfig2->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        // Safelist
        $resp = $firewall->decide(new ServerRequest('GET', '/health'));
        $this->assertTrue($resp->isPass());
        $this->assertSame('health', $resp->headers['X-Phirewall-Safelist'] ?? '');
        // Blocklist
        $blocked = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
        // Throttle
        $req = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.77']);
        $this->assertTrue($firewall->decide($req)->isPass());
        $this->assertTrue($firewall->decide($req)->isPass());
        $tooMany = $firewall->decide($req);
        $this->assertSame(Outcome::THROTTLED, $tooMany->outcome);
    }
}
