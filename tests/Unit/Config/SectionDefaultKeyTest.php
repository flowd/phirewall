<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Counter-section add() may omit $key: the rule then keys on the client IP
 * (Config IP resolver, else REMOTE_ADDR).
 */
final class SectionDefaultKeyTest extends TestCase
{
    private function request(string $remoteAddr, string $clientHeader = ''): ServerRequest
    {
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $remoteAddr]);

        return $clientHeader === '' ? $request : $request->withHeader('X-Real-Client', $clientHeader);
    }

    public function testThrottleDefaultKeyUsesConfiguredIpResolver(): void
    {
        $config = new Config(new InMemoryCache());
        // Header-based resolver: proves the default key uses it, not REMOTE_ADDR.
        $config->setIpResolver(
            static fn($request): ?string => $request->getHeaderLine('X-Real-Client') ?: null
        );
        $config->throttles->add('t', 1, 60); // no key

        $firewall = new Firewall($config);

        // Client A is throttled on its second request.
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-a'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('9.9.9.9', 'client-a'))->outcome);

        // Client B: same REMOTE_ADDR, different resolved key -> own counter.
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-b'))->isPass());
    }

    public function testEmptyStringKeyIsTreatedAsNoKeyAndSkipsTheRule(): void
    {
        $config = new Config(new InMemoryCache());
        // An extractor yielding '' is normalized to null, so the rule is skipped.
        // With limit 0 a real key would throttle the first request; '' lets it pass.
        $config->throttles->add('t', 0, 60, static fn(): string => '');

        $firewall = new Firewall($config);
        $this->assertTrue($firewall->decide($this->request('1.1.1.1'))->isPass());
    }

    public function testThrottleDefaultKeyFallsBackToRemoteAddr(): void
    {
        $config = new Config(new InMemoryCache()); // no IP resolver set
        $config->throttles->add('t', 1, 60); // no key

        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->request('1.1.1.1'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('1.1.1.1'))->outcome);
        // A different REMOTE_ADDR has its own counter.
        $this->assertTrue($firewall->decide($this->request('2.2.2.2'))->isPass());
    }

    public function testDefaultKeyResolvesIpResolverLazilyPerRequest(): void
    {
        $config = new Config(new InMemoryCache());
        // Add the rule BEFORE any IP resolver is configured.
        $config->throttles->add('t', 1, 60); // no key

        // Configure the resolver afterwards: a lazily-resolved default must pick it up.
        $config->setIpResolver(
            static fn($request): ?string => $request->getHeaderLine('X-Real-Client') ?: null
        );

        $firewall = new Firewall($config);

        // Keyed by the header (set after add()), not by the shared REMOTE_ADDR.
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-a'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('9.9.9.9', 'client-a'))->outcome);
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-b'))->isPass());
    }

    public function testComposedConfigResolvesDefaultKeyWithComposedResolver(): void
    {
        // Base config: a keyless throttle, no IP resolver.
        $base = new Config(new InMemoryCache());
        $base->throttles->add('t', 1, 60); // no key

        // Overlay config: sets a header-based IP resolver.
        $overlay = new Config(new InMemoryCache());
        $overlay->setIpResolver(
            static fn($request): ?string => $request->getHeaderLine('X-Real-Client') ?: null
        );

        // Composed config inherits the overlay's resolver and the base's keyless rule.
        $composed = $base->with($overlay);
        $firewall = new Firewall($composed);

        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-a'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('9.9.9.9', 'client-a'))->outcome);
        // Same REMOTE_ADDR, different resolved client -> isolated (composed resolver used).
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'client-b'))->isPass());
    }

    public function testSlidingAndMultiDefaultKeyFallBackToRemoteAddr(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->sliding('s', 1, 60); // no key
        $config->throttles->multi('m', [1 => 1]); // no key

        $rules = $config->throttles->rules();
        $this->assertArrayHasKey('s', $rules);
        $this->assertArrayHasKey('m:1s', $rules);

        $firewall = new Firewall($config);
        $this->assertTrue($firewall->decide($this->request('3.3.3.3'))->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($this->request('3.3.3.3'))->outcome);
    }

    public function testFail2BanDefaultKeyUsesConfiguredIpResolver(): void
    {
        $config = new Config(new InMemoryCache());
        $config->setIpResolver(
            static fn($request): ?string => $request->getHeaderLine('X-Real-Client') ?: null
        );
        // threshold 2 (>= semantic): the 2nd matching request for a key bans it.
        $config->fail2ban->add('f', threshold: 2, period: 60, ban: 3600, filter: static fn(): bool => true);

        $firewall = new Firewall($config);

        // The attacker is banned on its 2nd request.
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'attacker'))->isPass());
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'attacker'))->isBlocked());

        // Bystander: same REMOTE_ADDR, different resolved key -> not banned.
        $this->assertTrue($firewall->decide($this->request('9.9.9.9', 'bystander'))->isPass());
    }

    public function testAllow2BanDefaultKeyFallsBackToRemoteAddr(): void
    {
        $config = new Config(new InMemoryCache()); // no resolver
        $config->allow2ban->add('a', threshold: 2, period: 60, banSeconds: 3600); // no key

        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->request('5.5.5.5'))->isPass()); // 1st
        $this->assertTrue($firewall->decide($this->request('5.5.5.5'))->isBlocked()); // 2nd reaches threshold
        // A different REMOTE_ADDR has its own counter and still passes.
        $this->assertTrue($firewall->decide($this->request('6.6.6.6'))->isPass());
    }

    public function testTrackDefaultKeyFallsBackToRemoteAddr(): void
    {
        $events = [];
        $dispatcher = new class ($events) implements EventDispatcherInterface {
            /** @param list<object> $events */
            public function __construct(public array &$events)
            {
            }

            public function dispatch(object $event): object
            {
                $this->events[] = $event;

                return $event;
            }
        };

        $config = new Config(new InMemoryCache(), $dispatcher); // no resolver
        $config->tracks->add('seen', period: 60, filter: static fn(): bool => true, limit: 5); // no key

        $firewall = new Firewall($config);
        $firewall->decide($this->request('7.7.7.7'));
        $firewall->decide($this->request('7.7.7.7'));
        $firewall->decide($this->request('8.8.8.8'));

        $trackHits = array_values(array_filter(
            $dispatcher->events,
            static fn(object $event): bool => $event instanceof TrackHit && $event->rule === 'seen'
        ));

        // Per-IP counter: 7.7.7.7 sees count 1 then 2, 8.8.8.8 sees 1.
        $this->assertSame('7.7.7.7', $trackHits[0]->key);
        $this->assertSame(1, $trackHits[0]->count);
        $this->assertSame(2, $trackHits[1]->count);
        $this->assertSame('8.8.8.8', $trackHits[2]->key);
        $this->assertSame(1, $trackHits[2]->count);
    }
}
