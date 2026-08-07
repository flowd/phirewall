<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class BlockOnSignalBanTest extends TestCase
{
    private function fail2BanConfig(): Config
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add(
            'login-ban',
            threshold: 2,
            period: 300,
            ban: 3600,
            filter: static fn(ServerRequestInterface $serverRequest): bool => false,
        );

        return $config;
    }

    private function recordFailureHandler(string $ruleName): RequestHandlerInterface
    {
        return new class ($ruleName) implements RequestHandlerInterface {
            public function __construct(private readonly string $ruleName)
            {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    $context->recordFailure($this->ruleName);
                }

                return new Response(200, ['X-Handler' => 'ok']);
            }
        };
    }

    private function recordHitHandler(string $ruleName): RequestHandlerInterface
    {
        return new class ($ruleName) implements RequestHandlerInterface {
            public function __construct(private readonly string $ruleName)
            {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    $context->recordHit($this->ruleName);
                }

                return new Response(200, ['X-Handler' => 'ok']);
            }
        };
    }

    private function request(): ServerRequestInterface
    {
        return new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
    }

    /**
     * Default: the banning signal never touches the current response; the ban
     * takes effect from the next request.
     */
    public function testSignalBanKeepsHandlerResponseByDefault(): void
    {
        $config = $this->fail2BanConfig();
        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->recordFailureHandler('login-ban');

        $this->assertSame(200, $middleware->process($this->request(), $handler)->getStatusCode());

        // Second failure crosses threshold 2 and bans, but the response stays the handler's.
        $banningResponse = $middleware->process($this->request(), $handler);
        $this->assertSame(200, $banningResponse->getStatusCode());
        $this->assertSame('ok', $banningResponse->getHeaderLine('X-Handler'));

        // The ban applies from the next request on.
        $this->assertSame(403, $middleware->process($this->request(), $handler)->getStatusCode());
    }

    public function testSignalBanBlocksCurrentRequestWhenEnabled(): void
    {
        $config = $this->fail2BanConfig();
        $config->enableBlockOnSignalBan();

        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->recordFailureHandler('login-ban');

        // Below the threshold the handler response passes through unchanged.
        $belowThreshold = $middleware->process($this->request(), $handler);
        $this->assertSame(200, $belowThreshold->getStatusCode());
        $this->assertSame('ok', $belowThreshold->getHeaderLine('X-Handler'));

        // The banning signal turns the current response into the blocked response.
        $banningResponse = $middleware->process($this->request(), $handler);
        $this->assertSame(403, $banningResponse->getStatusCode());
        $this->assertSame('', $banningResponse->getHeaderLine('X-Handler'));

        // Subsequent requests are blocked before the handler runs.
        $this->assertSame(403, $middleware->process($this->request(), $handler)->getStatusCode());
    }

    public function testAllow2BanSignalBanBlocksWithRetryAfterWhenEnabled(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableBlockOnSignalBan();
        // Signal-only rule: the closed filter keeps request-time counting off.
        $config->allow2ban->add(
            'expensive-ops',
            threshold: 2,
            period: 300,
            banSeconds: 3600,
            filter: static fn(ServerRequestInterface $serverRequest): bool => false,
        );
        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->recordHitHandler('expensive-ops');

        $this->assertSame(200, $middleware->process($this->request(), $handler)->getStatusCode());

        $banningResponse = $middleware->process($this->request(), $handler);
        $this->assertSame(403, $banningResponse->getStatusCode());
        $this->assertSame('3600', $banningResponse->getHeaderLine('Retry-After'));
    }

    /**
     * With response headers enabled the blocked response carries the same
     * X-Phirewall headers as a request-time fail2ban block.
     */
    public function testSignalBanBlockedResponseCarriesResponseHeaders(): void
    {
        $config = $this->fail2BanConfig();
        $config->enableBlockOnSignalBan();
        $config->enableResponseHeaders();

        $middleware = new Middleware($config, new Psr17Factory());
        $handler = $this->recordFailureHandler('login-ban');

        $middleware->process($this->request(), $handler);
        $banningResponse = $middleware->process($this->request(), $handler);

        $this->assertSame(403, $banningResponse->getStatusCode());
        $this->assertSame('fail2ban', $banningResponse->getHeaderLine('X-Phirewall'));
        $this->assertSame('login-ban', $banningResponse->getHeaderLine('X-Phirewall-Matched'));
    }

    /**
     * An unknown rule name or a signal on an already-banned key must not
     * produce a block, even with the flag enabled.
     */
    public function testNonBanningSignalsNeverBlock(): void
    {
        $config = $this->fail2BanConfig();
        $config->enableBlockOnSignalBan();

        $middleware = new Middleware($config, new Psr17Factory());

        $unknownRuleHandler = $this->recordFailureHandler('no-such-rule');
        $this->assertSame(200, $middleware->process($this->request(), $unknownRuleHandler)->getStatusCode());
    }

    public function testCompositionCarriesBlockOnSignalBan(): void
    {
        $base = new Config(new InMemoryCache());
        $layer = new Config(new InMemoryCache());
        $layer->enableBlockOnSignalBan();

        $this->assertTrue($base->with($layer)->blockOnSignalBanEnabled());
        $this->assertFalse($base->with(new Config(new InMemoryCache()))->blockOnSignalBanEnabled());
    }
}
