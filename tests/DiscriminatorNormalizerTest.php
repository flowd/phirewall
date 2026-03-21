<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;

final class DiscriminatorNormalizerTest extends TestCase
{
    /**
     * Create a Config with a deterministic clock to avoid flaky time-boundary issues.
     */
    private function createConfig(?EventDispatcherInterface $eventDispatcher = null): Config
    {
        $fakeClock = new FakeClock(1_200_000_000.0);
        $inMemoryCache = new InMemoryCache($fakeClock);

        return new Config($inMemoryCache, $eventDispatcher, clock: $fakeClock);
    }

    /**
     * Without a normalizer, "USER_A" and "user_a" are treated as separate discriminator keys.
     * Each variant gets its own counter, so neither should hit the throttle limit.
     */
    public function testWithoutNormalizerDifferentCasesCountSeparately(): void
    {
        $config = $this->createConfig();

        $config->throttle(
            'user-throttle',
            2,
            60,
            fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'USER_A');
        $requestLowerCase = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'user_a');

        // Two requests with "USER_A" — both should pass (limit is 2)
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // Two requests with "user_a" — both should pass (separate counter)
        $this->assertSame(Outcome::PASS, $firewall->decide($requestLowerCase)->outcome);
        $this->assertSame(Outcome::PASS, $firewall->decide($requestLowerCase)->outcome);
    }

    /**
     * With a strtolower normalizer, "USER_A" and "user_a" share the same counter.
     * After two requests (one of each variant), the third should be throttled.
     */
    public function testLowercaseNormalizerCountsCaseVariantsTogether(): void
    {
        $config = $this->createConfig();

        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->throttle(
            'user-throttle',
            2,
            60,
            fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'USER_A');
        $requestLowerCase = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'user_a');

        // First request with "USER_A" — count = 1, passes
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // Second request with "user_a" — normalized to same key, count = 2, passes
        $this->assertSame(Outcome::PASS, $firewall->decide($requestLowerCase)->outcome);

        // Third request — count = 3, exceeds limit of 2, should be throttled
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $firewallResult->outcome);
    }

    /**
     * The normalizer should also apply to fail2ban discriminator keys.
     * With strtolower normalizer, alternating case variants should share
     * the same fail counter and trigger a ban after the threshold.
     */
    public function testNormalizerAppliesToFail2BanKeys(): void
    {
        $config = $this->createConfig();

        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->fail2ban(
            'login-ban',
            2,       // threshold
            60,      // period
            300,     // ban seconds
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        $serverRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-Login-Failed', '1')
            ->withHeader('X-User-Id', 'USER_A');
        $failedLowerCase = (new ServerRequest('POST', '/login'))
            ->withHeader('X-Login-Failed', '1')
            ->withHeader('X-User-Id', 'user_a');

        // First failure with "USER_A" — count = 1, passes
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // Second failure with "user_a" — normalized to same key, count = 2, triggers ban
        $firewallResult = $firewall->decide($failedLowerCase);
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('fail2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('login-ban', $firewallResult->headers['X-Phirewall-Matched'] ?? '');

        // Even a clean request from the same normalized key should be banned
        $cleanRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-User-Id', 'User_A');
        $bannedResult = $firewall->decide($cleanRequest);
        $this->assertSame(Outcome::BLOCKED, $bannedResult->outcome);
    }

    /**
     * The normalizer should apply to track discriminator keys.
     * With strtolower normalizer, requests with different case variants
     * should share the same counter, producing incrementing TrackHit counts.
     */
    public function testNormalizerAppliesToTrackKeys(): void
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

        $config = $this->createConfig($dispatcher);

        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->track(
            'user-activity',
            period: 60,
            filter: fn($request): bool => true,
            key: fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'USER_A');
        $requestLowerCase = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'user_a');
        $requestMixedCase = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'User_A');

        $firewall->decide($serverRequest);
        $firewall->decide($requestLowerCase);
        $firewall->decide($requestMixedCase);

        $trackHits = array_values(array_filter(
            $dispatcher->events,
            fn(object $event): bool => $event instanceof TrackHit
        ));

        $this->assertCount(3, $trackHits);

        // All three should share the same counter thanks to the normalizer
        $this->assertSame(1, $trackHits[0]->count);
        $this->assertSame(2, $trackHits[1]->count);
        $this->assertSame(3, $trackHits[2]->count);
    }

    /**
     * When no normalizer is set, getDiscriminatorNormalizer() returns null
     * and different case keys count separately (original behavior preserved).
     */
    public function testNullNormalizerPreservesOriginalBehavior(): void
    {
        $config = $this->createConfig();

        $this->assertNull($config->getDiscriminatorNormalizer());

        $config->throttle(
            'user-throttle',
            1,
            60,
            fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'USER_A');
        $requestLowerCase = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'user_a');

        // First request with "USER_A" — count = 1, passes (limit = 1)
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // "USER_A" is now at its limit; next request should be throttled
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($serverRequest)->outcome);

        // "user_a" uses a separate counter and should still pass
        $this->assertSame(Outcome::PASS, $firewall->decide($requestLowerCase)->outcome);
    }

    /**
     * Regression: when the ban is triggered by an uppercase key variant,
     * the ban must still block requests with a different-case variant.
     * Previously, ban() received the unnormalized key while lookups used
     * the normalized key, causing the ban to be stored under a different
     * cache key than the one checked on subsequent requests.
     */
    public function testFail2BanBanCreatedWithUppercaseBlocksLowercaseVariant(): void
    {
        $config = $this->createConfig();

        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->fail2ban(
            'login-ban',
            2,       // threshold
            60,      // period
            300,     // ban seconds
            filter: fn($request): bool => $request->getHeaderLine('X-Login-Failed') === '1',
            key: fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        // Trigger ban with UPPERCASE variant only
        $serverRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-Login-Failed', '1')
            ->withHeader('X-User-Id', 'USER_A');

        // First failure — count = 1, passes
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // Second failure — count = 2, triggers ban
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($serverRequest)->outcome);

        // Now a clean request from lowercase variant must also be blocked
        $lowercaseCleanRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-User-Id', 'user_a');
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($lowercaseCleanRequest)->outcome);

        // Mixed-case variant must also be blocked
        $mixedCaseCleanRequest = (new ServerRequest('POST', '/login'))
            ->withHeader('X-User-Id', 'User_A');
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($mixedCaseCleanRequest)->outcome);
    }

    /**
     * Regression: Allow2Ban should also use normalized keys consistently
     * for ban creation and lookup when a discriminator normalizer is set.
     */
    public function testAllow2BanNormalizerConsistency(): void
    {
        $config = $this->createConfig();

        $config->setDiscriminatorNormalizer(fn(string $key): string => strtolower($key));

        $config->allow2ban->add(
            'abuse-ban',
            threshold: 2,
            period: 60,
            banSeconds: 300,
            key: fn($request): string => $request->getHeaderLine('X-User-Id')
        );

        $firewall = new Firewall($config);

        // Trigger ban with UPPERCASE variant only
        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'USER_B');

        // First hit — count = 1, passes
        $this->assertSame(Outcome::PASS, $firewall->decide($serverRequest)->outcome);

        // Second hit — count = 2, triggers ban
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($serverRequest)->outcome);

        // Lowercase variant must also be blocked
        $lowercaseRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-User-Id', 'user_b');
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($lowercaseRequest)->outcome);
    }

    /**
     * setDiscriminatorNormalizer() should return the Config instance for fluent chaining.
     */
    public function testNormalizerSetterReturnsSelfForFluency(): void
    {
        $config = $this->createConfig();

        $result = $config->setDiscriminatorNormalizer(fn(string $key): string => $key);

        $this->assertSame($config, $result);
    }
}
