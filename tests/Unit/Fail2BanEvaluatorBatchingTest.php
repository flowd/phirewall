<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\CallCountingCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * The per-rule ban-key existence checks are batched
 * into a single getMultiple() instead of one has() per rule, while leaving the
 * block/ban behaviour unchanged.
 */
final class Fail2BanEvaluatorBatchingTest extends TestCase
{
    private function makeFailedLoginRequest(string $ip = '5.6.7.8'): ServerRequest
    {
        return (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => $ip]))
            ->withHeader('X-Login-Failed', '1');
    }

    private function configureRules(Config $config, int $ruleCount): void
    {
        for ($index = 0; $index < $ruleCount; ++$index) {
            $config->fail2ban->add(
                'login-' . $index,
                threshold: 2,
                period: 5,
                ban: 10,
                filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
                key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
            );
        }
    }

    public function testBanKeyExistenceChecksAreBatchedIntoOneGetMultiple(): void
    {
        $countingCache = new CallCountingCache(new InMemoryCache());
        $config = new Config($countingCache);
        $this->configureRules($config, 4);

        $firewall = new Firewall($config);
        $countingCache->resetCounts();

        // Nothing banned yet: a single batched getMultiple covers all four rules' ban keys.
        $firewall->decide($this->makeFailedLoginRequest());

        $this->assertSame(1, $countingCache->getMultipleCalls, 'Ban-key existence should be batched into one getMultiple');
        $this->assertSame(0, $countingCache->hasCalls, 'No per-rule has() round-trips should remain on the common path');
    }

    public function testNoCacheLookupWhenEveryKeyIsNull(): void
    {
        $countingCache = new CallCountingCache(new InMemoryCache());
        $config = new Config($countingCache);
        $config->fail2ban(
            'login',
            threshold: 2,
            period: 5,
            ban: 10,
            filter: fn($request): bool => true,
            key: fn($request): ?string => null,
        );

        $firewall = new Firewall($config);
        $countingCache->resetCounts();

        $this->assertTrue($firewall->decide($this->makeFailedLoginRequest())->isPass());
        $this->assertSame(0, $countingCache->getMultipleCalls, 'A request matching no candidate rule must not touch the cache');
        $this->assertSame(0, $countingCache->hasCalls);
    }

    public function testBehaviourUnchangedAcrossMultipleRules(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->enableResponseHeaders();
        // Two rules sharing the same key/filter; the FIRST rule (by insertion order)
        // must own the ban decision.
        $config->fail2ban(
            'first',
            threshold: 2,
            period: 5,
            ban: 10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );
        $config->fail2ban(
            'second',
            threshold: 2,
            period: 5,
            ban: 10,
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1',
        );

        $firewall = new Firewall($config);
        $request = $this->makeFailedLoginRequest('9.9.9.9');

        // threshold=2: the 1st failure passes; the 2nd failure trips the first rule.
        $this->assertTrue($firewall->decide($request)->isPass());
        $banned = $firewall->decide($request);
        $this->assertTrue($banned->isBlocked());
        $this->assertSame('first', $banned->headers['X-Phirewall-Matched'] ?? '');

        // A subsequent request is blocked by the already-banned key of the first rule.
        $blocked = $firewall->decide($request);
        $this->assertTrue($blocked->isBlocked());
        $this->assertSame('first', $blocked->headers['X-Phirewall-Matched'] ?? '');
    }
}
