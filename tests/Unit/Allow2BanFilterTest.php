<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Allow2ban gains an optional filter: only matching requests are counted, matching
 * requests still pass until the threshold, and a null filter keeps counting every
 * request (the classic hard volume cap).
 */
final class Allow2BanFilterTest extends TestCase
{
    private function loginAttempt(string $ip): ServerRequest
    {
        return new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function pageView(string $ip): ServerRequest
    {
        return new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    private function loginAttemptFilter(): \Closure
    {
        return fn($request): bool => $request->getMethod() === 'POST'
            && $request->getUri()->getPath() === '/login';
    }

    public function testFilterOnlyCountsMatchingRequests(): void
    {
        $config = new Config(new InMemoryCache());
        $config->allow2ban->add(
            'login-brute-force',
            threshold: 3,
            period: 60,
            banSeconds: 600,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
            filter: $this->loginAttemptFilter(),
        );

        $firewall = new Firewall($config);

        // Page views do not match the filter, so they never count and never ban.
        for ($i = 0; $i < 5; ++$i) {
            $this->assertTrue($firewall->decide($this->pageView('10.0.0.1'))->isPass());
        }

        $this->assertFalse($firewall->isBanned('login-brute-force', '10.0.0.1', BanType::Allow2Ban));

        // Login attempts match: 1st and 2nd pass, the 3rd reaches the threshold and bans.
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.1'))->isPass());
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.1'))->isPass());
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.1'))->isBlocked());
    }

    public function testBannedKeyBlocksEveryRequestRegardlessOfFilter(): void
    {
        $config = new Config(new InMemoryCache());
        $config->allow2ban->add(
            'login-brute-force',
            threshold: 2,
            period: 60,
            banSeconds: 600,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
            filter: $this->loginAttemptFilter(),
        );

        $firewall = new Firewall($config);

        // Trip the ban with two matching requests.
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.2'))->isPass());
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.2'))->isBlocked());

        // A non-matching request from the banned key is still blocked.
        $this->assertTrue($firewall->decide($this->pageView('10.0.0.2'))->isBlocked());
    }

    public function testNullFilterCountsEveryRequest(): void
    {
        $config = new Config(new InMemoryCache());
        $config->allow2ban->add(
            'volume-cap',
            threshold: 2,
            period: 60,
            banSeconds: 600,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
        );

        $firewall = new Firewall($config);
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.3']);

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isBlocked());
    }

    public function testSignalOnlyRuleWithNeverMatchingFilter(): void
    {
        $config = new Config(new InMemoryCache());
        // filter never matches: the pre-handler path never counts; recordHit drives the ban.
        $config->allow2ban->add(
            'reported-abuse',
            threshold: 2,
            period: 60,
            banSeconds: 600,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
            filter: static fn(): bool => false,
        );

        $handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
                if ($context instanceof RequestContext) {
                    $context->recordHit('reported-abuse');
                }

                return new Response(200);
            }
        };

        $middleware = new Middleware($config, new Psr17Factory());
        $request = new ServerRequest('GET', '/api', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.4']);

        // Pre-handler filter never matches, so both requests pass; the recorded hits count.
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $this->assertSame(200, $middleware->process($request, $handler)->getStatusCode());
        $this->assertTrue($config->banManager()->isBanned('reported-abuse', '10.0.0.4', BanType::Allow2Ban));
    }

    public function testFilterSurvivesConfigOverlay(): void
    {
        $base = new Config(new InMemoryCache());
        $overlay = new Config(new InMemoryCache());
        $overlay->allow2ban->add(
            'login-brute-force',
            threshold: 2,
            period: 60,
            banSeconds: 600,
            key: fn($request): string => $request->getServerParams()['REMOTE_ADDR'],
            filter: $this->loginAttemptFilter(),
        );

        $composed = $base->with($overlay);

        $rule = $composed->allow2ban->rules()['login-brute-force'];
        $this->assertInstanceOf(ClosureRequestMatcher::class, $rule->filter());

        $firewall = new Firewall($composed);
        // The overlaid filter still gates counting after composition.
        $this->assertTrue($firewall->decide($this->pageView('10.0.0.5'))->isPass());
        $this->assertTrue($firewall->decide($this->pageView('10.0.0.5'))->isPass());
        $this->assertFalse($firewall->isBanned('login-brute-force', '10.0.0.5', BanType::Allow2Ban));

        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.5'))->isPass());
        $this->assertTrue($firewall->decide($this->loginAttempt('10.0.0.5'))->isBlocked());
    }

    public function testRuleFilterDefaultsToNull(): void
    {
        $rule = new Allow2BanRule(
            'no-filter',
            2,
            60,
            600,
            new ClosureKeyExtractor(fn($request): string => '127.0.0.1'),
        );

        $this->assertNull($rule->filter());
    }
}
