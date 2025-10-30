<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Portable;

use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class PortableConfigTest extends TestCase
{
    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testBlocklistPathEquals(): void
    {
        $portableConfig = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin')); // block /admin

        $config = $portableConfig->toConfig(new InMemoryCache());
        $middleware = new Middleware($config);

        $request1 = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(200, $request1->getStatusCode());

        $request2 = $middleware->process(new ServerRequest('GET', '/admin'), $this->handler());
        $this->assertSame(403, $request2->getStatusCode());
        $this->assertSame('blocklist', $request2->getHeaderLine('X-Phirewall'));
        $this->assertSame('admin', $request2->getHeaderLine('X-Phirewall-Matched'));
    }

    public function testThrottleByIpAndRateLimitHeaders(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableRateLimitHeaders()
            ->throttle('ip', 1, 30, PortableConfig::keyIp());

        $config = $portableConfig->toConfig(new InMemoryCache());
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $req = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
        $ok = $middleware->process($req, $handler);
        $this->assertSame(200, $ok->getStatusCode());
        $this->assertSame('1', $ok->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('0', $ok->getHeaderLine('X-RateLimit-Remaining'));

        $throttled = $middleware->process($req, $handler);
        $this->assertSame(429, $throttled->getStatusCode());
        $this->assertSame('1', $throttled->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('0', $throttled->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertGreaterThanOrEqual(1, (int)$throttled->getHeaderLine('X-RateLimit-Reset'));
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
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $r = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $fail = $r->withHeader('X-Login-Failed', '1');
        $this->assertSame(200, $middleware->process($fail, $handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($fail, $handler)->getStatusCode());
        $b = $middleware->process($r, $handler);
        $this->assertSame(403, $b->getStatusCode());
        $this->assertSame('fail2ban', $b->getHeaderLine('X-Phirewall'));
        $this->assertSame('login', $b->getHeaderLine('X-Phirewall-Matched'));
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
        $middleware = new Middleware($config);
        $handler = $this->handler();

        // Safelist
        $resp = $middleware->process(new ServerRequest('GET', '/health'), $handler);
        $this->assertSame(200, $resp->getStatusCode());
        $this->assertSame('health', $resp->getHeaderLine('X-Phirewall-Safelist'));
        // Blocklist
        $blocked = $middleware->process(new ServerRequest('GET', '/admin'), $handler);
        $this->assertSame(403, $blocked->getStatusCode());
        // Throttle
        $req = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.77']);
        $this->assertSame(200, $middleware->process($req, $handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($req, $handler)->getStatusCode());
        $tooMany = $middleware->process($req, $handler);
        $this->assertSame(429, $tooMany->getStatusCode());
    }
}
