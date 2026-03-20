<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class DisableToggleTest extends TestCase
{
    public function testEnabledByDefault(): void
    {
        $config = new Config(new InMemoryCache());

        $this->assertTrue($config->isEnabled());
    }

    public function testDisableSkipsBlocklist(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');
        $config->disable();

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/admin', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $firewallResult = $firewall->decide($serverRequest);

        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::PASS, $firewallResult->outcome);
    }

    public function testDisableSkipsThrottle(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->throttle('ip', 1, 60, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');
        $config->disable();

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // All requests should pass even though the limit is 1
        for ($i = 0; $i < 5; ++$i) {
            $firewallResult = $firewall->decide($serverRequest);
            $this->assertTrue($firewallResult->isPass(), sprintf('Request %d should pass when firewall is disabled', $i));
            $this->assertSame(Outcome::PASS, $firewallResult->outcome);
        }
    }

    public function testReEnableAppliesRules(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');
        $config->disable();

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/admin', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // While disabled, request passes
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame(Outcome::PASS, $firewallResult->outcome);

        // Re-enable the firewall
        $config->enable();

        // Now the request should be blocked
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
    }

    public function testSetEnabledToggle(): void
    {
        $config = new Config(new InMemoryCache());

        $this->assertTrue($config->isEnabled());

        $config->setEnabled(false);
        $this->assertFalse($config->isEnabled());

        $config->setEnabled(true);
        $this->assertTrue($config->isEnabled());

        $config->setEnabled(false);
        $this->assertFalse($config->isEnabled());
    }

    public function testMiddlewareShortCircuitsWhenDisabled(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklist('blockedPath', fn($request): bool => $request->getUri()->getPath() === '/admin');
        $config->disable();

        $middleware = new Middleware($config, new Psr17Factory());

        $handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                return new Response(200, ['X-Handler' => 'ok']);
            }
        };

        $serverRequest = new ServerRequest('GET', '/admin', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
        $response = $middleware->process($serverRequest, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok', $response->getHeaderLine('X-Handler'));
    }

    public function testDisabledFirewallDoesNotIncrementCounters(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $limit = 3;
        $period = 60;
        $config->throttle('ip', $limit, $period, fn($request): string => $request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1');
        $config->disable();

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // Make several requests while disabled (more than the limit)
        for ($i = 0; $i < 5; ++$i) {
            $firewallResult = $firewall->decide($serverRequest);
            $this->assertTrue($firewallResult->isPass());
        }

        // Re-enable the firewall
        $config->enable();

        // All requests up to the limit should pass, proving no counters were incremented while disabled
        for ($i = 1; $i <= $limit; ++$i) {
            $firewallResult = $firewall->decide($serverRequest);
            $this->assertTrue(
                $firewallResult->isPass(),
                sprintf('Request %d of %d should pass because no counters were incremented while disabled', $i, $limit)
            );
        }

        // The next request should exceed the limit
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }
}
