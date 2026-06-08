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
    }

    public function testTrackSectionAdd(): void
    {
        $config = new Config(new InMemoryCache());
        $config->tracks->add('api', 60, fn($r): true => true, fn($r): string => '127.0.0.1');

        $this->assertCount(1, $config->tracks->rules());
    }

    public function testThrottleSectionMulti(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->multi('api', [1 => 3, 60 => 100], fn($r): string => '127.0.0.1');

        $rules = $config->throttles->rules();
        $this->assertCount(2, $rules);
        $this->assertArrayHasKey('api:1s', $rules);
        $this->assertArrayHasKey('api:60s', $rules);

        $serverRequest = new ServerRequest('GET', '/');
        $this->assertSame(3, $rules['api:1s']->resolveLimit($serverRequest));
        $this->assertSame(1, $rules['api:1s']->resolvePeriod($serverRequest));
        $this->assertSame(100, $rules['api:60s']->resolveLimit($serverRequest));
        $this->assertSame(60, $rules['api:60s']->resolvePeriod($serverRequest));
    }

    public function testMatchingSafelistShortCircuitsBlocklist(): void
    {
        $config = new Config(new InMemoryCache());

        $config->safelists->add('deny-none', fn($r): false => false);
        $config->safelists->add('health', fn($r): bool => $r->getUri()->getPath() === '/health');

        $this->assertCount(2, $config->safelists->rules());

        $config->blocklists->add('block-all', fn(): true => true);
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/health');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }
}
