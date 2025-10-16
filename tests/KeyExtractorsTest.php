<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class KeyExtractorsTest extends TestCase
{
    private function handler(): \Psr\Http\Server\RequestHandlerInterface
    {
        return new class () implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return new \Nyholm\Psr7\Response(200);
            }
        };
    }

    public function testThrottleByIpExtractor(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->throttle('ip', 1, 30, KeyExtractors::ip());
        $middleware = new Middleware($config);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertSame(200, $middleware->process($request, $this->handler())->getStatusCode());
        $secondResponse = $middleware->process($request, $this->handler());
        $this->assertSame(429, $secondResponse->getStatusCode());
        $this->assertSame('ip', $secondResponse->getHeaderLine('X-Flowd-Firewall-Matched'));
    }

    public function testTrackByPathAndMethodExtractors(): void
    {
        $cache = new InMemoryCache();
        $events = new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];
            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };
        $config = new Config($cache, $events);
        // Track GET on /metrics
        $config->track(
            'hits',
            60,
            filter: function ($request): bool {
                return KeyExtractors::method()($request) === 'GET' && KeyExtractors::path()($request) === '/metrics';
            },
            key: KeyExtractors::path()
        );
        $middleware = new Middleware($config);
        $handler = $this->handler();

        $metricsRequest = new ServerRequest('GET', '/metrics');
        $response = $middleware->process($metricsRequest, $handler);
        $this->assertSame(200, $response->getStatusCode());
        // Second request to increment counter
        $middleware->process($metricsRequest, $handler);

        // Ensure counter incremented to 2 in cache under expected track key
        $counterKey = (new \ReflectionClass(Middleware::class))->getMethod('trackKey');
        $counterKey->setAccessible(true);
        /** @var string $key */
        $key = $counterKey->invoke(new Middleware($config), 'hits', '/metrics');
        $count = $cache->get($key, 0);
        $this->assertSame(2, $count);
    }

    public function testHeaderAndUserAgentExtractors(): void
    {
        $userAgentExtractor = KeyExtractors::userAgent();
        $customHeaderExtractor = KeyExtractors::header('X-Custom');
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', 'UA-1')
            ->withHeader('X-Custom', 'foo');
        $this->assertSame('UA-1', $userAgentExtractor($request));
        $this->assertSame('foo', $customHeaderExtractor($request));
    }
}
