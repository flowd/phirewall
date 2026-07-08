<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Fail2BanMatched;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Fail2ban match semantics: every filter match is blocked (403). A match below
 * the threshold blocks via Fail2BanMatched; the Nth match bans via Fail2BanBanned.
 */
final class Fail2BanMatchSemanticsTest extends TestCase
{
    private function probeRequest(string $ip = '203.0.113.5'): ServerRequest
    {
        return new ServerRequest('GET', '/wp-admin/setup.php', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    public function testFilterMatchBelowThresholdBlocksWithMatchedDecision(): void
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
        $config = new Config(new InMemoryCache(), $dispatcher);
        $config->enableResponseHeaders();

        $config->fail2ban->add(
            'scanner-probes',
            threshold: 3,
            period: 60,
            ban: 600,
            filter: fn($request): bool => str_starts_with($request->getUri()->getPath(), '/wp-admin'),
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $result = $firewall->decide($this->probeRequest());

        $this->assertSame(Outcome::BLOCKED, $result->outcome);
        $this->assertSame('fail2ban', $result->headers['X-Phirewall'] ?? '');
        $this->assertSame('scanner-probes', $result->headers['X-Phirewall-Matched'] ?? '');

        $matched = array_values(array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanMatched));
        $this->assertCount(1, $matched);
        /** @var Fail2BanMatched $event */
        $event = $matched[0];
        $this->assertSame('scanner-probes', $event->rule);
        $this->assertSame('203.0.113.5', $event->key);
        $this->assertSame(3, $event->threshold);
        $this->assertSame(60, $event->period);
        $this->assertSame(1, $event->count);

        // No ban yet: the key is not banned below the threshold.
        $this->assertFalse($firewall->isBanned('scanner-probes', '203.0.113.5', BanType::Fail2Ban));
        $this->assertCount(0, array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanBanned));
    }

    public function testBanningMatchDispatchesOnlyBannedEvent(): void
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
        $config = new Config(new InMemoryCache(), $dispatcher);
        $config->fail2ban->add(
            'scanner-probes',
            threshold: 2,
            period: 60,
            ban: 600,
            filter: fn($request): bool => str_starts_with($request->getUri()->getPath(), '/wp-admin'),
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $firewall->decide($this->probeRequest());       // 1st match: Fail2BanMatched
        $firewall->decide($this->probeRequest());        // 2nd match: bans

        // Exactly one Matched (the sub-threshold 1st match) and one Banned (the 2nd match):
        // the banning match dispatches only Fail2BanBanned, never both.
        $this->assertCount(1, array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanMatched));
        $this->assertCount(1, array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanBanned));
        $this->assertTrue($firewall->isBanned('scanner-probes', '203.0.113.5', BanType::Fail2Ban));
    }

    public function testNonMatchingRequestIsNeverBlocked(): void
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add(
            'scanner',
            threshold: 2,
            period: 60,
            ban: 600,
            filter: fn($request): bool => str_starts_with($request->getUri()->getPath(), '/wp-admin'),
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $clean = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.7']);

        // A request the filter does not match is never blocked by fail2ban.
        $this->assertTrue($firewall->decide($clean)->isPass());
        $this->assertTrue($firewall->decide($clean)->isPass());
    }

    public function testRecordedFailureSignalNeitherBlocksNorDispatchesMatched(): void
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
        $config = new Config(new InMemoryCache(), $dispatcher);
        // Signal-only rule: the filter never matches a request; recordFailure drives it.
        $config->fail2ban->add(
            'reported-login',
            threshold: 2,
            period: 60,
            ban: 600,
            filter: static fn(): bool => false,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
        );

        $handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    $context->recordFailure('reported-login');
                }

                return new Response(200);
            }
        };

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.9']);

        // First signal: counts but does not block the current request.
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $this->assertCount(0, array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanMatched));

        // Second signal: reaches the threshold and bans; still returns 200 for this request.
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $this->assertTrue($config->banManager()->isBanned('reported-login', '192.0.2.9', BanType::Fail2Ban));

        // The now-banned key is blocked on its next request.
        $this->assertTrue((new Firewall($config))->decide($request)->isBlocked());
    }
}
