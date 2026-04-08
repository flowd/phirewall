<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class TrustedBotMatcherTest extends TestCase
{
    public function testRealGooglebotIsSafelisted(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->add('block-all', fn($r): bool => true);

        // Use mocked DNS resolvers for deterministic testing
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: fn(string $ip): string => 'crawl-66-249-66-1.googlebot.com',
            forwardResolve: fn(string $host): array => ['66.249.66.1'],
        );
        $config->safelists->addRule(new \Flowd\Phirewall\Config\Rule\SafelistRule('bots-test', $trustedBotMatcher));

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        ], null, '1.1', ['REMOTE_ADDR' => '66.249.66.1']);

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::SAFELISTED, $firewallResult->outcome);
    }

    public function testFakeGooglebotIsNotSafelisted(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: fn(string $ip): string => 'evil-server.example.com',
            forwardResolve: fn(string $host): array => ['1.2.3.4'],
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $matchResult = $trustedBotMatcher->match($serverRequest);
        $this->assertFalse($matchResult->isMatch());
    }

    public function testNoUserAgentDoesNotMatch(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher();
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testNoIpDoesNotMatch(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher();
        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ]);

        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testNonBotUserAgentDoesNotMatch(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher();
        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testBingbotVerification(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: fn(string $ip): string => 'msnbot-157-55-39-1.search.msn.com',
            forwardResolve: fn(string $host): array => ['157.55.39.1'],
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Mozilla/5.0 (compatible; bingbot/2.0)',
        ], null, '1.1', ['REMOTE_ADDR' => '157.55.39.1']);

        $matchResult = $trustedBotMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('trusted_bot', $matchResult->source());
        $this->assertSame('bingbot', $matchResult->metadata()['bot_ua']);
    }

    public function testAdditionalBotIsRecognized(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [['ua' => 'mybot', 'hostname' => '.example.com']],
            reverseResolve: fn(string $ip): string => 'crawler.example.com',
            forwardResolve: fn(string $host): array => ['10.0.0.1'],
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'MyBot/1.0',
        ], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertTrue($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testRdnsReturnsIpOnFailure(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: fn(string $ip): string => $ip, // gethostbyaddr failure returns the IP
            forwardResolve: fn(string $host): array => [$host],
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testForwardResolveMismatch(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: fn(string $ip): string => 'crawl-66-249-66-1.googlebot.com',
            forwardResolve: fn(string $host): array => ['99.99.99.99'], // different IP
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '66.249.66.1']);

        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testConfigSectionIntegration(): void
    {
        $config = new Config(new InMemoryCache());
        $safelistSection = $config->safelists->trustedBots();

        $this->assertCount(1, $config->safelists->rules());
        $this->assertArrayHasKey('trusted-bots', $config->safelists->rules());
        $this->assertSame($config->safelists, $safelistSection); // fluent
    }

    public function testDnsCachingAvoidsDuplicateLookups(): void
    {
        $lookupCount = 0;
        $inMemoryCache = new InMemoryCache();
        $trustedBotMatcher = new TrustedBotMatcher(
            reverseResolve: function (string $ip) use (&$lookupCount): string {
                ++$lookupCount;
                return 'crawl-66-249-66-1.googlebot.com';
            },
            forwardResolve: fn(string $host): array => ['66.249.66.1'],
            cache: $inMemoryCache,
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '66.249.66.1']);

        $this->assertTrue($trustedBotMatcher->match($serverRequest)->isMatch());
        $this->assertTrue($trustedBotMatcher->match($serverRequest)->isMatch());
        $this->assertTrue($trustedBotMatcher->match($serverRequest)->isMatch());

        // DNS should only be called once — subsequent calls served from cache
        $this->assertSame(1, $lookupCount);
    }

    public function testCachedFalseResultIsRespected(): void
    {
        $inMemoryCache = new InMemoryCache();
        $trustedBotMatcher = new TrustedBotMatcher(
            reverseResolve: fn(string $ip): string => 'evil.example.com',
            forwardResolve: fn(string $host): array => ['1.2.3.4'],
            cache: $inMemoryCache,
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // First call: DNS lookup, result cached as false
        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
        // Second call: served from cache
        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
    }

    public function testWithoutCacheDnsCalledEveryTime(): void
    {
        $lookupCount = 0;
        $trustedBotMatcher = new TrustedBotMatcher(
            reverseResolve: function (string $ip) use (&$lookupCount): string {
                ++$lookupCount;
                return 'crawl-66-249-66-1.googlebot.com';
            },
            forwardResolve: fn(string $host): array => ['66.249.66.1'],
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '66.249.66.1']);

        $trustedBotMatcher->match($serverRequest);
        $trustedBotMatcher->match($serverRequest);
        $trustedBotMatcher->match($serverRequest);

        $this->assertSame(3, $lookupCount);
    }

    public function testInvalidAdditionalBotThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        /** @phpstan-ignore argument.type (intentionally passing invalid data to test validation) */
        new TrustedBotMatcher(additionalBots: [['wrong_key' => 'value']]);
    }

    public function testEmptyBotUaThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TrustedBotMatcher(additionalBots: [['ua' => '', 'hostname' => '.example.com']]);
    }

    public function testHostnameSuffixWithoutLeadingDotThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('must start with a dot');
        new TrustedBotMatcher(additionalBots: [['ua' => 'mybot', 'hostname' => 'example.com']]);
    }

    public function testZeroCacheTtlThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        /** @phpstan-ignore argument.type (intentionally testing validation) */
        new TrustedBotMatcher(cacheTtl: 0);
    }

    public function testNegativeCacheTtlThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        /** @phpstan-ignore argument.type (intentionally testing validation) */
        new TrustedBotMatcher(cacheTtl: -1);
    }

    public function testNegativeResultCachedBriefly(): void
    {
        $inMemoryCache = new InMemoryCache();
        $lookups = 0;
        $trustedBotMatcher = new TrustedBotMatcher(
            reverseResolve: function (string $ip) use (&$lookups): string {
                ++$lookups;
                return 'evil.example.com';
            },
            forwardResolve: fn(string $host): array => ['1.2.3.4'],
            cache: $inMemoryCache,
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        // First call: DNS lookup, negative result cached for 5 minutes
        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
        // Second call: served from cache, no new lookup
        $this->assertFalse($trustedBotMatcher->match($serverRequest)->isMatch());
        $this->assertSame(1, $lookups);
    }

    public function testCustomIpResolverIsUsed(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            reverseResolve: fn(string $ip): string => 'crawl-66-249-66-1.googlebot.com',
            forwardResolve: fn(string $host): array => ['10.0.0.99'],
            ipResolver: fn($r): string => '10.0.0.99', // custom resolver
        );

        $serverRequest = new ServerRequest('GET', '/', [
            'User-Agent' => 'Googlebot/2.1',
        ], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']); // REMOTE_ADDR is ignored

        $this->assertTrue($trustedBotMatcher->match($serverRequest)->isMatch());
    }
}
