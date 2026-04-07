<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\KeyExtractors;
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

final class RequestAttributeIntegrationTest extends TestCase
{
    /**
     * Create a handler that records a failure via the request context.
     */
    private function failureRecordingHandler(string $ruleName, string $key): RequestHandlerInterface
    {
        return new class ($ruleName, $key) implements RequestHandlerInterface {
            public function __construct(
                private readonly string $ruleName,
                private readonly string $key,
            ) {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    $context->recordFailure($this->ruleName, $this->key);
                }

                return new Response(200, ['X-Handler' => 'ok']);
            }
        };
    }

    /**
     * Create a handler that simply returns a 200 response.
     */
    private function passThroughHandler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                return new Response(200, ['X-Handler' => 'ok']);
            }
        };
    }

    /**
     * Create a simple event collector.
     *
     * @return EventDispatcherInterface&object{events: list<object>}
     */
    private function eventCollector(): EventDispatcherInterface
    {
        return new class () implements EventDispatcherInterface {
            /** @var list<object> */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };
    }

    public function testMiddlewareAttachesContextAndHandlerRecordsFailure(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        // filter returns false — decide() won't count, only context signals will
        $config->fail2ban(
            'login-brute-force',
            threshold: 5,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $handler = $this->failureRecordingHandler('login-brute-force', '10.0.0.1');

        $response = $middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok', $response->getHeaderLine('X-Handler'));
    }

    public function testBanTriggersOnThreshold(): void
    {
        $dispatcher = $this->eventCollector();
        $cache = new InMemoryCache();
        $config = new Config($cache, $dispatcher);
        $config->enableResponseHeaders();
        // filter returns false — only context signals increment the fail counter
        $config->fail2ban(
            'login-brute-force',
            threshold: 3,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $handler = $this->failureRecordingHandler('login-brute-force', '10.0.0.1');

        // First 2 requests record failures below threshold
        $middleware->process($request, $handler);
        $middleware->process($request, $handler);

        // Third request triggers ban
        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());

        // Verify ban event was dispatched
        $banEvents = array_values(array_filter(
            $dispatcher->events,
            fn(object $event): bool => $event instanceof Fail2BanBanned,
        ));
        $this->assertCount(1, $banEvents);
        $this->assertSame('login-brute-force', $banEvents[0]->rule);
        $this->assertSame('10.0.0.1', $banEvents[0]->key);

        // Fourth request should be blocked by the firewall's decide() (already banned)
        $fourthResponse = $middleware->process($request, $this->passThroughHandler());
        $this->assertSame(403, $fourthResponse->getStatusCode());
        $this->assertSame('fail2ban', $fourthResponse->getHeaderLine('X-Phirewall'));
    }

    public function testFailOpenSwallowsContextProcessingErrors(): void
    {
        $dispatcher = $this->eventCollector();
        $innerCache = new InMemoryCache();
        $failingCache = new class ($innerCache) implements \Psr\SimpleCache\CacheInterface {
            private int $setCallCount = 0;

            public function __construct(private readonly InMemoryCache $inner)
            {
            }

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->inner->get($key, $default);
            }

            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                ++$this->setCallCount;
                if ($this->setCallCount > 2) {
                    throw new \RuntimeException('Cache write failed during context processing');
                }

                return $this->inner->set($key, $value, $ttl);
            }

            public function delete(string $key): bool
            {
                return $this->inner->delete($key);
            }

            public function clear(): bool
            {
                return $this->inner->clear();
            }

            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                return $this->inner->getMultiple($keys, $default);
            }

            /** @param iterable<string, mixed> $values */
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
            {
                return $this->inner->setMultiple($values, $ttl);
            }

            public function deleteMultiple(iterable $keys): bool
            {
                return $this->inner->deleteMultiple($keys);
            }

            public function has(string $key): bool
            {
                return $this->inner->has($key);
            }
        };

        $config = new Config($failingCache, $dispatcher);
        // filter returns false — only context signals trigger processing
        $config->fail2ban(
            'login-brute-force',
            threshold: 1,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $handler = $this->failureRecordingHandler('login-brute-force', '10.0.0.1');

        // Should not throw — fail-open swallows the error
        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());

        // Verify FirewallError event was dispatched
        $errorEvents = array_values(array_filter(
            $dispatcher->events,
            fn(object $event): bool => $event instanceof FirewallError,
        ));
        $this->assertCount(1, $errorEvents);
    }

    public function testFailClosedThrowsOnContextProcessingError(): void
    {
        $innerCache = new InMemoryCache();
        $failingCache = new class ($innerCache) implements \Psr\SimpleCache\CacheInterface {
            private int $setCallCount = 0;

            public function __construct(private readonly InMemoryCache $inner)
            {
            }

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->inner->get($key, $default);
            }

            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                ++$this->setCallCount;
                if ($this->setCallCount > 2) {
                    throw new \RuntimeException('Cache write failed');
                }

                return $this->inner->set($key, $value, $ttl);
            }

            public function delete(string $key): bool
            {
                return $this->inner->delete($key);
            }

            public function clear(): bool
            {
                return $this->inner->clear();
            }

            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                return $this->inner->getMultiple($keys, $default);
            }

            /** @param iterable<string, mixed> $values */
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
            {
                return $this->inner->setMultiple($values, $ttl);
            }

            public function deleteMultiple(iterable $keys): bool
            {
                return $this->inner->deleteMultiple($keys);
            }

            public function has(string $key): bool
            {
                return $this->inner->has($key);
            }
        };

        $config = new Config($failingCache);
        $config->setFailOpen(false);
        // filter returns false — only context signals trigger processing
        $config->fail2ban(
            'login-brute-force',
            threshold: 1,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);
        $handler = $this->failureRecordingHandler('login-brute-force', '10.0.0.1');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cache write failed');
        $middleware->process($request, $handler);
    }

    public function testContextAvailableWhenRequestPasses(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);

        $capture = new \stdClass();
        $capture->context = null;
        $handler = new class ($capture) implements RequestHandlerInterface {
            public function __construct(private readonly \stdClass $capture)
            {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $this->capture->context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                return new Response(200);
            }
        };

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('GET', '/');

        $middleware->process($request, $handler);

        $this->assertInstanceOf(RequestContext::class, $capture->context);
        $this->assertTrue($capture->context->getResult()->isPass());
        $this->assertFalse($capture->context->hasRecordedSignals());
    }

    public function testNoContextOnBlockedRequests(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->blocklist('admin', fn($request): bool => $request->getUri()->getPath() === '/admin');

        $capture = new \stdClass();
        $capture->called = false;
        $handler = new class ($capture) implements RequestHandlerInterface {
            public function __construct(private readonly \stdClass $capture)
            {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $this->capture->called = true;
                return new Response(200);
            }
        };

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('GET', '/admin');

        $response = $middleware->process($request, $handler);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertFalse($capture->called, 'Handler should not be called for blocked requests');
    }

    public function testUnknownRuleNameIsIgnored(): void
    {
        $cache = new InMemoryCache();
        $config = new Config($cache);
        $config->fail2ban(
            'login-brute-force',
            threshold: 3,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Handler records a failure for a non-existent rule
        $handler = $this->failureRecordingHandler('nonexistent-rule', '10.0.0.1');

        // Should not throw — unknown rule is silently ignored
        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testDiscriminatorNormalizerAppliedToRecordedFailures(): void
    {
        $dispatcher = $this->eventCollector();
        $cache = new InMemoryCache();
        $config = new Config($cache, $dispatcher);
        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));
        $config->fail2ban(
            'login-brute-force',
            threshold: 2,
            period: 300,
            ban: 3600,
            filter: fn($request): bool => false,
            key: KeyExtractors::ip(),
        );

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        // Record failures with mixed case — normalizer should unify them
        $handler1 = $this->failureRecordingHandler('login-brute-force', 'User@Example.COM');
        $handler2 = $this->failureRecordingHandler('login-brute-force', 'user@example.com');

        $middleware->process($request, $handler1);
        $middleware->process($request, $handler2);

        // Ban event should fire with normalized key
        $banEvents = array_values(array_filter(
            $dispatcher->events,
            fn(object $event): bool => $event instanceof Fail2BanBanned,
        ));
        $this->assertCount(1, $banEvents);
        $this->assertSame('user@example.com', $banEvents[0]->key);
    }
}
