<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\CallCountingCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The per-rule ban-key existence checks are batched
 * into a single getMultiple(), and the Retry-After TTL lookup is deferred to the
 * at-most-once block construction, so the common path performs no per-rule has()/get()
 * round-trips. The block/ban behaviour is unchanged.
 */
final class Allow2BanEvaluatorBatchingTest extends TestCase
{
    private function makeRequest(string $ip = '1.2.3.4'): ServerRequest
    {
        return new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function configureRules(Config $config, int $ruleCount): void
    {
        for ($index = 0; $index < $ruleCount; ++$index) {
            $config->allow2ban->add(
                'limit-' . $index,
                threshold: 100,
                period: 60,
                banSeconds: 3600,
                key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
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

        // Nothing banned and below threshold: one batched getMultiple covers all four ban keys,
        // and no Retry-After TTL lookup is performed on the common path.
        $this->assertTrue($firewall->decide($this->makeRequest('10.0.0.1'))->isPass());

        $this->assertSame(1, $countingCache->getMultipleCalls, 'Ban-key existence should be batched into one getMultiple');
        $this->assertSame(0, $countingCache->hasCalls, 'No per-rule has() round-trips should remain on the common path');
        $this->assertSame(0, $countingCache->getCalls, 'No per-rule get() round-trips should remain on the common path');
    }

    public function testTtlLookupHappensAtMostOnceWhenBlocked(): void
    {
        $countingCache = new CallCountingCache(new InMemoryCache());
        $config = new Config($countingCache);
        $config->enableResponseHeaders();
        // Several already-banned rules. The first block is captured once; the loop keeps
        // going but the already-banned branch performs at most one Retry-After TTL lookup.
        $this->configureRules($config, 3);

        $firewall = new Firewall($config);
        $request = $this->makeRequest('10.0.0.2');

        // Pre-ban every rule's key directly via the ban manager.
        foreach (['limit-0', 'limit-1', 'limit-2'] as $rule) {
            $config->banManager()->ban($rule, '10.0.0.2', 3600, BanType::Allow2Ban);
        }

        $countingCache->resetCounts();

        $result = $firewall->decide($request);
        $this->assertTrue($result->isBlocked());
        $this->assertSame('limit-0', $result->headers['X-Phirewall-Matched'] ?? null, 'First rule owns the block decision');
        $this->assertSame(1, $countingCache->getMultipleCalls, 'Existence is still a single batched getMultiple');
        $this->assertSame(1, $countingCache->ttlRemainingCalls, 'Retry-After TTL is read at most once even with several banned rules');
    }

    public function testKeyCollidingRulesBanTheSharedKeyOnce(): void
    {
        // Two rule names normalize to the same ban key ('dup a' and 'dup_a') and key on the same
        // value, so they share one ban key. The first rule bans it; the in-loop snapshot write-back
        // makes the second rule observe that ban and skip re-banning, dispatching one ban event
        // rather than one per colliding rule.
        $dispatcher = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;

                return $event;
            }
        };
        $config = new Config(new InMemoryCache(), $dispatcher);
        $keyByIp = fn($request): string => $request->getServerParams()['REMOTE_ADDR'];
        $config->allow2ban->add('dup a', threshold: 1, period: 60, banSeconds: 3600, key: $keyByIp);
        $config->allow2ban->add('dup_a', threshold: 1, period: 60, banSeconds: 3600, key: $keyByIp);

        $firewall = new Firewall($config);
        $result = $firewall->decide($this->makeRequest('10.0.0.9'));

        $this->assertTrue($result->isBlocked());
        $banEvents = array_filter($dispatcher->events, static fn(object $event): bool => $event instanceof Allow2BanBanned);
        $this->assertCount(1, $banEvents, 'Key-colliding rules must ban the shared key once, not once per rule');
    }
}
