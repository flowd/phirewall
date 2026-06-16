<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An IP-aware matcher used as a fail2ban or track FILTER (not just as a
 * safelist/blocklist rule) late-binds the client-IP resolver through the
 * evaluating Config, the same as safelist/blocklist matchers.
 */
final class FilterIpResolverLateBindingTest extends TestCase
{
    public function testFail2BanFilterLateBindsToConfigResolver(): void
    {
        $config = new Config(new InMemoryCache());
        $config->setIpResolver($this->headerResolver('X-Real-IP'));
        // Filter is an IpMatcher with no explicit resolver; the key is also default
        // (null), so both resolve the client IP through the Config at request time.
        $config->fail2ban->addRule(new Fail2BanRule('bad-ip', 1, 60, 3600, new IpMatcher(['203.0.113.7']), null));

        $firewall = new Firewall($config);

        // threshold=1: the offender (arriving via X-Real-IP) is filtered and banned
        // on the first hit - which only happens if the filter read X-Real-IP, not
        // the harmless REMOTE_ADDR it would have captured before late-binding.
        $offender = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $this->assertTrue($firewall->decide($offender)->isBlocked());

        // A different forwarded client is not filtered, so it is not banned.
        $other = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '198.51.100.9');
        $this->assertTrue($firewall->decide($other)->isPass());
    }

    public function testTrackFilterLateBindsToConfigResolver(): void
    {
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $config = new Config(new InMemoryCache(), $events);
        $config->setIpResolver($this->headerResolver('X-Real-IP'));

        $config->tracks->addRule(new TrackRule('bad-ip', 60, new IpMatcher(['203.0.113.7']), null, null));

        $firewall = new Firewall($config);

        // The offender arrives via X-Real-IP; the track filter late-binds and matches,
        // emitting a TrackHit. With REMOTE_ADDR-only resolution it would not match.
        $offender = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $firewall->decide($offender);

        $trackHits = array_filter($events->events, static fn(object $event): bool => $event instanceof TrackHit);
        $this->assertCount(1, $trackHits);
    }

    /**
     * A resolver that reads the client IP from the named header (null when absent).
     *
     * @return \Closure(ServerRequestInterface): ?string
     */
    private function headerResolver(string $header): \Closure
    {
        return static function (ServerRequestInterface $serverRequest) use ($header): ?string {
            $value = $serverRequest->getHeaderLine($header);
            return $value === '' ? null : $value;
        };
    }
}
