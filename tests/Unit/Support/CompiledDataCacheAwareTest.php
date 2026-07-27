<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class CompiledDataCacheAwareTest extends TestCase
{
    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * @return RequestMatcherInterface&CompiledDataCacheAware&object{received: ?CompiledDataCache}
     */
    private function recordingAwareMatcher(): RequestMatcherInterface
    {
        return new class () implements RequestMatcherInterface, CompiledDataCacheAware {
            public ?CompiledDataCache $received = null;

            public function match(ServerRequestInterface $serverRequest): MatchResult
            {
                return MatchResult::noMatch();
            }

            public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
            {
                $this->received = $compiledDataCache;
            }
        };
    }

    public function testConfigCarriesTheCompiledDataCache(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertNull($config->compiledDataCache());

        $compiledDataCache = new CompiledDataCache(vfsStream::setup('cache')->url());
        $config->setCompiledDataCache($compiledDataCache);

        $this->assertSame($compiledDataCache, $config->compiledDataCache());
    }

    public function testCompositionInheritsTheCacheFromTheBaseLayer(): void
    {
        $baseCache = new CompiledDataCache(vfsStream::setup('cache')->url() . '/base');
        $overlayCache = new CompiledDataCache(vfsStream::setup('cache2')->url() . '/overlay');

        $base = (new Config(new InMemoryCache()))->setCompiledDataCache($baseCache);
        $overlay = (new Config(new InMemoryCache()))->setCompiledDataCache($overlayCache);

        $this->assertSame($baseCache, $base->with($overlay)->compiledDataCache());
    }

    public function testFirewallInjectsTheCacheIntoAwareMatchersOfEverySection(): void
    {
        $compiledDataCache = new CompiledDataCache(vfsStream::setup('cache')->url());
        $config = (new Config(new InMemoryCache()))->setCompiledDataCache($compiledDataCache);
        $keyExtractor = new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => '203.0.113.5');

        $matchers = [
            'safelist' => $this->recordingAwareMatcher(),
            'blocklist' => $this->recordingAwareMatcher(),
            'fail2ban' => $this->recordingAwareMatcher(),
            'allow2ban' => $this->recordingAwareMatcher(),
            'track' => $this->recordingAwareMatcher(),
            'throttleScope' => $this->recordingAwareMatcher(),
        ];

        $config->safelists->addRule(new SafelistRule('s', $matchers['safelist']));
        $config->blocklists->addRule(new BlocklistRule('b', $matchers['blocklist']));
        $config->fail2ban->addRule(new Fail2BanRule('f', 3, 60, 600, $matchers['fail2ban'], $keyExtractor));
        $config->allow2ban->addRule(new Allow2BanRule('a', 3, 60, 600, $keyExtractor, $matchers['allow2ban']));
        $config->tracks->addRule(new TrackRule('t', 60, $matchers['track'], $keyExtractor, null));
        $config->throttles->addRule(new Config\Rule\ThrottleRule('th', 10, 60, $keyExtractor, false, $matchers['throttleScope']));

        new Firewall($config);

        foreach ($matchers as $section => $matcher) {
            $this->assertSame($compiledDataCache, $matcher->received, "Matcher of section {$section} must receive the cache.");
        }
    }

    public function testNoInjectionWithoutAConfiguredCache(): void
    {
        $config = new Config(new InMemoryCache());
        $matcher = $this->recordingAwareMatcher();
        $config->blocklists->addRule(new BlocklistRule('b', $matcher));

        new Firewall($config);

        $this->assertNull($matcher->received);
    }

    public function testIpMatcherCompilesLazilyAndWritesAnArtifact(): void
    {
        $root = vfsStream::setup('cache');
        $compiledDataCache = new CompiledDataCache($root->url());

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher(['203.0.113.0/24', '198.51.100.7']);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $request = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']);
        $this->assertTrue($ipMatcher->match($request)->isMatch());
        $this->assertNotSame([], $root->getChildren(), 'The compiled tables must be persisted.');
    }

    public function testIpMatcherConsumesTheCompiledArtifact(): void
    {
        $root = vfsStream::setup('cache');
        $compiledDataCache = new CompiledDataCache($root->url());
        $entries = ['203.0.113.0/24'];

        // Seed the content-addressed artifact with tables for a DIFFERENT
        // address; the matcher must follow the artifact, proving it never
        // recompiles the entries.
        $identifier = 'ip-matcher-' . sha1(implode("\n", $entries));
        $crafted = ['cidrs' => [], 'exact' => [inet_pton('192.0.2.1') => true]];
        $compiledDataCache->load($identifier, [], static fn(): array => $crafted);
        CompiledDataCache::clearProcessCache();

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher($entries);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $craftedRequest = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.1']);
        $originalRequest = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']);

        $this->assertTrue($ipMatcher->match($craftedRequest)->isMatch());
        $this->assertFalse($ipMatcher->match($originalRequest)->isMatch());
    }
}
