<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matcher-provided diagnostic headers: a matcher opts in per match via the
 * `diagnostic_headers` metadata key; Config::enableDiagnosticsHeaders() copies
 * them onto blocked responses. Names must be X-Phirewall-prefixed and values
 * are sanitized.
 */
final class DiagnosticHeadersTest extends TestCase
{
    /**
     * @param array<string, scalar|array<string, scalar>> $metadata
     */
    private function matcherWith(array $metadata): RequestMatcherInterface
    {
        return new class ($metadata) implements RequestMatcherInterface {
            /** @param array<string, scalar|array<string, scalar>> $metadata */
            public function __construct(private readonly array $metadata)
            {
            }

            public function match(ServerRequestInterface $serverRequest): MatchResult
            {
                return MatchResult::matched('crs-engine', $this->metadata);
            }
        };
    }

    private function request(string $ip = '203.0.113.5'): ServerRequest
    {
        return new ServerRequest('GET', '/probe', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    public function testBlocklistCopiesDiagnosticHeadersWhenEnabled(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableDiagnosticsHeaders();

        $config->blocklists->addRule(new BlocklistRule('crs', $this->matcherWith([
            'diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => 942100],
        ])));

        $result = (new Firewall($config))->decide($this->request());

        $this->assertTrue($result->isBlocked());
        $this->assertSame('942100', $result->headers['X-Phirewall-Owasp-Rule'] ?? null);
    }

    public function testDiagnosticHeadersAreAbsentByDefault(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->addRule(new BlocklistRule('crs', $this->matcherWith([
            'diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => 942100],
        ])));

        $result = (new Firewall($config))->decide($this->request());

        $this->assertTrue($result->isBlocked());
        $this->assertArrayNotHasKey('X-Phirewall-Owasp-Rule', $result->headers);
    }

    public function testUnprefixedNamesAndUnsafeValuesAreSanitized(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableDiagnosticsHeaders();

        $config->blocklists->addRule(new BlocklistRule('crs', $this->matcherWith([
            'diagnostic_headers' => [
                'Retry-After' => '0',
                'X-Custom-Header' => 'skipped',
                'X-Phirewall-Rule' => "9421\r\n00",
            ],
        ])));

        $result = (new Firewall($config))->decide($this->request());

        $this->assertTrue($result->isBlocked());
        $this->assertArrayNotHasKey('Retry-After', $result->headers);
        $this->assertArrayNotHasKey('X-Custom-Header', $result->headers);
        $this->assertSame('942100', $result->headers['X-Phirewall-Rule'] ?? null);
    }

    public function testFail2BanFilterMatchCarriesDiagnosticHeaders(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableDiagnosticsHeaders();

        $config->fail2ban->addRule(new Fail2BanRule(
            'crs-probes',
            threshold: 2,
            period: 60,
            banSeconds: 600,
            requestMatcher: $this->matcherWith(['diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => '942100']]),
            keyExtractor: new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR']),
        ));

        $firewall = new Firewall($config);

        // Sub-threshold match (Fail2BanMatched path).
        $matched = $firewall->decide($this->request());
        $this->assertTrue($matched->isBlocked());
        $this->assertSame('942100', $matched->headers['X-Phirewall-Owasp-Rule'] ?? null);

        // Banning match (Fail2BanBanned path).
        $banned = $firewall->decide($this->request());
        $this->assertTrue($banned->isBlocked());
        $this->assertSame('942100', $banned->headers['X-Phirewall-Owasp-Rule'] ?? null);

        // Banned-key block: no filter evaluation, no diagnostic headers.
        $blocked = $firewall->decide($this->request());
        $this->assertTrue($blocked->isBlocked());
        $this->assertArrayNotHasKey('X-Phirewall-Owasp-Rule', $blocked->headers);
    }

    public function testAllow2BanBanningRequestCarriesDiagnosticHeaders(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableDiagnosticsHeaders();

        $config->allow2ban->addRule(new Allow2BanRule(
            'crs-volume',
            threshold: 1,
            period: 60,
            banSeconds: 600,
            keyExtractor: new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR']),
            requestMatcher: $this->matcherWith(['diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => '942100']]),
        ));

        $firewall = new Firewall($config);

        // Banning request: the filter matched, so its diagnostics are attached.
        $banned = $firewall->decide($this->request());
        $this->assertTrue($banned->isBlocked());
        $this->assertSame('942100', $banned->headers['X-Phirewall-Owasp-Rule'] ?? null);

        // Banned-key block: the filter is bypassed, no diagnostic headers.
        $blocked = $firewall->decide($this->request());
        $this->assertTrue($blocked->isBlocked());
        $this->assertArrayNotHasKey('X-Phirewall-Owasp-Rule', $blocked->headers);
    }

    public function testDeprecatedOwaspToggleDrivesTheSameFlag(): void
    {
        $config = new Config(new InMemoryCache());
        $config->enableOwaspDiagnosticsHeader();

        $this->assertTrue($config->diagnosticsHeadersEnabled());
    }

    public function testPortableConfigMaterializesDiagnosticsHeadersOption(): void
    {
        $portableConfig = PortableConfig::fromArray(['options' => ['diagnosticsHeaders' => true]]);
        $config = (new Config(new InMemoryCache()))->with($portableConfig);

        $this->assertTrue($config->diagnosticsHeadersEnabled());
    }

    public function testPortableConfigStillMaterializesTheLegacyOwaspOption(): void
    {
        $portableConfig = PortableConfig::fromArray(['options' => ['owaspDiagnosticsHeader' => true]]);
        $config = (new Config(new InMemoryCache()))->with($portableConfig);

        $this->assertTrue($config->diagnosticsHeadersEnabled());
    }

    public function testBlocklistMatchedCarriesTheMatchResult(): void
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
        $config->blocklists->addRule(new BlocklistRule('crs', $this->matcherWith([
            'diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => '942100'],
        ])));

        (new Firewall($config))->decide($this->request());

        $matched = array_values(array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof BlocklistMatched));
        $this->assertCount(1, $matched);
        /** @var BlocklistMatched $event */
        $event = $matched[0];
        $this->assertInstanceOf(MatchResult::class, $event->matchResult);
        $this->assertSame('crs-engine', $event->matchResult->source());
        $this->assertSame(['X-Phirewall-Owasp-Rule' => '942100'], $event->matchResult->metadata()['diagnostic_headers'] ?? null);
    }

    public function testTrackHitCarriesTheFilterMatch(): void
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
        $config->tracks->addRule(new TrackRule(
            'observer',
            60,
            $this->matcherWith(['diagnostic_headers' => ['X-Phirewall-Rule' => 'observed']]),
            new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR']),
            null,
        ));

        (new Firewall($config))->decide($this->request());

        $hits = array_values(array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof TrackHit));
        $this->assertCount(1, $hits);
        /** @var TrackHit $event */
        $event = $hits[0];
        $this->assertInstanceOf(MatchResult::class, $event->matchResult);
        $this->assertSame(['X-Phirewall-Rule' => 'observed'], $event->matchResult->metadata()['diagnostic_headers'] ?? null);
    }

    public function testFail2BanBannedCarriesTheFilterMatch(): void
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
        $config->fail2ban->addRule(new Fail2BanRule(
            'crs-probes',
            threshold: 1,
            period: 60,
            banSeconds: 600,
            requestMatcher: $this->matcherWith(['diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => '942100']]),
            keyExtractor: new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => $serverRequest->getServerParams()['REMOTE_ADDR']),
        ));

        (new Firewall($config))->decide($this->request());

        $banned = array_values(array_filter($dispatcher->events, static fn(object $e): bool => $e instanceof Fail2BanBanned));
        $this->assertCount(1, $banned);
        /** @var Fail2BanBanned $event */
        $event = $banned[0];
        $this->assertInstanceOf(MatchResult::class, $event->matchResult);
        $this->assertSame('crs-engine', $event->matchResult->source());
    }
}
