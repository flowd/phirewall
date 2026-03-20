<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Section\BlocklistSection;
use Flowd\Phirewall\Config\Section\Fail2BanSection;
use Flowd\Phirewall\Config\Section\SafelistSection;
use Flowd\Phirewall\Config\Section\ThrottleSection;
use Flowd\Phirewall\Config\Section\TrackSection;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class ConfigSectionsTest extends TestCase
{
    public function testSectionsExist(): void
    {
        $config = new Config(new InMemoryCache());

        $this->assertInstanceOf(SafelistSection::class, $config->safelists);
        $this->assertInstanceOf(BlocklistSection::class, $config->blocklists);
        $this->assertInstanceOf(ThrottleSection::class, $config->throttles);
        $this->assertInstanceOf(Fail2BanSection::class, $config->fail2ban);
        $this->assertInstanceOf(TrackSection::class, $config->tracks);
    }

    public function testSafelistSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->safelists->add('health', fn($r): bool => $r->getUri()->getPath() === '/health');

        $this->assertCount(1, $config->safelists->rules());
        // Deprecated getter still works
        $this->assertCount(1, $config->getSafelistRules());
    }

    public function testBlocklistSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->add('admin', fn($r): bool => $r->getUri()->getPath() === '/admin');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/admin');
        $this->assertTrue($firewall->decide($serverRequest)->isBlocked());
    }

    public function testThrottleSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->add('ip', 2, 60, fn($r): string => '127.0.0.1');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($serverRequest)->outcome);
    }

    public function testThrottleSectionSliding(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->sliding('api', 2, 60, fn($r): string => '127.0.0.1');

        $rules = $config->throttles->rules();
        $this->assertCount(1, $rules);
        $this->assertArrayHasKey('api', $rules);
        $this->assertTrue($rules['api']->isSliding());
    }

    public function testFail2BanSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add(
            'login',
            2,
            60,
            900,
            fn($r): bool => $r->getUri()->getPath() === '/login',
            fn($r): string => '127.0.0.1',
        );

        $this->assertCount(1, $config->fail2ban->rules());
        $this->assertCount(1, $config->getFail2BanRules());
    }

    public function testTrackSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->tracks->add('api', 60, fn($r): true => true, fn($r): string => '127.0.0.1');

        $this->assertCount(1, $config->tracks->rules());
        $this->assertCount(1, $config->getTrackRules());
    }

    public function testDeprecatedMethodsStillWork(): void
    {
        $config = new Config(new InMemoryCache());

        // Old API
        $config->safelist('health', fn($r): true => true);
        $config->blocklist('admin', fn($r): true => true);
        $config->throttle('ip', 10, 60, fn($r): string => '127.0.0.1');
        $config->fail2ban('login', 5, 60, 900, fn($r): true => true, fn($r): string => '127.0.0.1');
        $config->track('api', 60, fn($r): true => true, fn($r): string => '127.0.0.1');

        // Rules land in the sections
        $this->assertCount(1, $config->safelists->rules());
        $this->assertCount(1, $config->blocklists->rules());
        $this->assertCount(1, $config->throttles->rules());
        $this->assertCount(1, $config->fail2ban->rules());
        $this->assertCount(1, $config->tracks->rules());
    }

    public function testMixOldAndNewApi(): void
    {
        $config = new Config(new InMemoryCache());

        // Mix both APIs
        $config->safelist('old-way', fn($r): false => false);

        $config->safelists->add('new-way', fn($r): bool => $r->getUri()->getPath() === '/health');

        $this->assertCount(2, $config->safelists->rules());
        $this->assertCount(2, $config->getSafelistRules());

        // Both are honored by Firewall
        $config->blocklists->add('block-all', fn(): true => true);
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/health');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }
}
