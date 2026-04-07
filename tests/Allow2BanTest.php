<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class Allow2BanTest extends TestCase
{
    private function makeRequest(string $ip = '1.2.3.4'): ServerRequest
    {
        return new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    public function testRequestsAllowedBeforeThreshold(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->allow2ban->add('test', threshold: 5, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.1');

        for ($i = 0; $i < 4; ++$i) {
            $this->assertTrue($firewall->decide($serverRequest)->isPass(), sprintf('Request %d should pass', $i));
        }
    }

    public function testBannedOnThresholdRequest(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableResponseHeaders();

        $config->allow2ban->add('test', threshold: 5, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.2');

        for ($i = 0; $i < 4; ++$i) {
            $firewall->decide($serverRequest); // passes
        }

        $firewallResult = $firewall->decide($serverRequest); // 5th -- hits threshold
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('allow2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('test', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
        $this->assertSame('3600', $firewallResult->headers['Retry-After'] ?? '');
    }

    public function testRemainsBlockedAfterBanSet(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->allow2ban->add('test', threshold: 3, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.3');

        // Exhaust threshold
        for ($i = 0; $i < 3; ++$i) {
            $firewall->decide($serverRequest);
        }

        // Subsequent requests should all be blocked via ban key
        for ($i = 0; $i < 5; ++$i) {
            $result = $firewall->decide($serverRequest);
            $this->assertTrue($result->isBlocked(), "Request after ban should be blocked");
            $this->assertArrayHasKey('Retry-After', $result->headers);
        }
    }

    public function testDifferentKeysAreIsolated(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->allow2ban->add('test', threshold: 3, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);

        // Exhaust ip1
        for ($i = 0; $i < 3; ++$i) {
            $firewall->decide($this->makeRequest('192.168.1.1'));
        }

        // ip2 should still pass
        $this->assertTrue($firewall->decide($this->makeRequest('192.168.1.2'))->isPass());
    }

    public function testAllow2BanBannedEventIsFired(): void
    {
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache, $dispatcher);
        $config->allow2ban->add('test', threshold: 2, period: 60, banSeconds: 900, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('5.6.7.8');

        $firewall->decide($serverRequest);
        $firewall->decide($serverRequest); // triggers ban

        $banEvents = array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Allow2BanBanned);
        $this->assertCount(1, $banEvents);

        /** @var Allow2BanBanned $event */
        $event = array_values($banEvents)[0];
        $this->assertSame('test', $event->rule);
        $this->assertSame('5.6.7.8', $event->key);
        $this->assertSame(2, $event->threshold);
        $this->assertSame(60, $event->period);
        $this->assertSame(900, $event->banSeconds);
        $this->assertSame(2, $event->count);
    }

    public function testNullKeySkipsRule(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->allow2ban->add('test', threshold: 1, period: 60, banSeconds: 3600, key: fn($req): ?string => null);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.1');

        // Even with threshold=1, null key means rule is skipped
        for ($i = 0; $i < 5; ++$i) {
            $this->assertTrue($firewall->decide($serverRequest)->isPass(), sprintf('Request %d should pass when key is null', $i));
        }
    }

    public function testAddRuleDirectly(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);

        $allow2BanRule = new Allow2BanRule(
            'direct-rule',
            2,
            60,
            900,
            new ClosureKeyExtractor(fn($req): string => $req->getServerParams()['REMOTE_ADDR']),
        );
        $config->allow2ban->addRule($allow2BanRule);
        $config->enableResponseHeaders();

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.5');

        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('allow2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('direct-rule', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testMultipleRulesFirstMatchWins(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableResponseHeaders();

        $config->allow2ban->add('strict', threshold: 2, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);
        $config->allow2ban->add('lenient', threshold: 100, period: 60, banSeconds: 3600, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.6');

        $firewall->decide($serverRequest);
        $firewallResult = $firewall->decide($serverRequest); // 2nd request hits strict threshold
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('strict', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThresholdZeroThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule threshold must be >= 1, got 0.');

        new Allow2BanRule(
            'test',
            0,
            60,
            3600,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testThresholdNegativeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule threshold must be >= 1, got -5.');

        new Allow2BanRule(
            'test',
            -5,
            60,
            3600,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testPeriodZeroThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule period must be >= 1, got 0.');

        new Allow2BanRule(
            'test',
            5,
            0,
            3600,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testPeriodNegativeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule period must be >= 1, got -10.');

        new Allow2BanRule(
            'test',
            5,
            -10,
            3600,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testBanSecondsZeroThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule banSeconds must be >= 1, got 0.');

        new Allow2BanRule(
            'test',
            5,
            60,
            0,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testBanSecondsNegativeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule banSeconds must be >= 1, got -1.');

        new Allow2BanRule(
            'test',
            5,
            60,
            -1,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testEmptyNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Allow2BanRule name must not be empty.');

        new Allow2BanRule(
            '',
            5,
            60,
            3600,
            new ClosureKeyExtractor(fn($req): string => '127.0.0.1'),
        );
    }

    public function testDistinctKeysWithSimilarCharactersAreIsolated(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        // Use a key extractor that returns a custom header value (user-controllable input)
        $config->allow2ban->add(
            'api-limit',
            threshold: 3,
            period: 60,
            banSeconds: 3600,
            key: fn($req): string => $req->getHeaderLine('X-Api-Key'),
        );

        $firewall = new Firewall($config);

        // Two keys that would collide under the old normalizeKeyComponent() approach:
        // alice@domain.com -> alice_domain_com
        // alice-domain-com -> alice_domain_com
        $serverRequest = (new ServerRequest('GET', '/'))->withHeader('X-Api-Key', 'alice@domain.com');
        $requestB = (new ServerRequest('GET', '/'))->withHeader('X-Api-Key', 'alice-domain-com');

        // Exhaust threshold for key A
        for ($i = 0; $i < 3; ++$i) {
            $firewall->decide($serverRequest);
        }

        // Key A should now be banned
        $this->assertTrue($firewall->decide($serverRequest)->isBlocked(), 'alice@domain.com should be banned');

        // Key B must still be allowed (different hash, no collision)
        $this->assertTrue($firewall->decide($requestB)->isPass(), 'alice-domain-com must not be affected by alice@domain.com ban');

        // Verify key B can independently accumulate hits without being blocked by key A's ban
        $this->assertTrue($firewall->decide($requestB)->isPass(), 'alice-domain-com 2nd request should still pass');
    }

    public function testHitCounterResetAfterBan(): void
    {
        $fakeClock = new FakeClock();
        $inMemoryCache = new InMemoryCache($fakeClock);
        $config = new Config($inMemoryCache);
        $config->allow2ban->add('test', threshold: 3, period: 60, banSeconds: 5, key: fn($req): string => $req->getServerParams()['REMOTE_ADDR']);

        $firewall = new Firewall($config);
        $serverRequest = $this->makeRequest('10.0.0.99');

        // 1) First 2 requests pass (below threshold)
        for ($i = 0; $i < 2; ++$i) {
            $this->assertTrue($firewall->decide($serverRequest)->isPass(), sprintf('Request %d should pass', $i + 1));
        }

        // 2) 3rd request triggers the ban
        $result = $firewall->decide($serverRequest);
        $this->assertTrue($result->isBlocked(), '3rd request should trigger ban');

        // 3) Simulate ban expiring by advancing the clock past banSeconds
        $fakeClock->advance(6.0);

        // 4) After ban expires, requests should pass again (hit counter was reset)
        $result = $firewall->decide($serverRequest);
        $this->assertTrue($result->isPass(), 'First request after ban expires should pass');

        $result = $firewall->decide($serverRequest);
        $this->assertTrue($result->isPass(), 'Second request after ban expires should pass');

        // 5) Verify it takes another 3 requests to get banned again
        //    We already sent 2 above, so the 3rd should trigger the ban
        $result = $firewall->decide($serverRequest);
        $this->assertTrue($result->isBlocked(), '3rd request in new window should trigger ban again');
    }
}
