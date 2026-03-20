<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Matchers\SuspiciousHeadersMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class SuspiciousHeadersMatcherTest extends TestCase
{
    public function testRequestMissingAcceptIsBlocked(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->suspiciousHeaders();

        $firewall = new Firewall($config);
        // No Accept, Accept-Language, or Accept-Encoding headers
        $serverRequest = new ServerRequest('GET', '/');

        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
    }

    public function testRequestWithAllDefaultHeadersPasses(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher();
        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('Accept', 'text/html')
            ->withHeader('Accept-Language', 'en-US')
            ->withHeader('Accept-Encoding', 'gzip');

        $this->assertFalse($suspiciousHeadersMatcher->match($serverRequest)->isMatch());
    }

    public function testRequestMissingOneDefaultHeaderMatches(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher();
        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('Accept', 'text/html')
            ->withHeader('Accept-Encoding', 'gzip');
        // Missing Accept-Language

        $matchResult = $suspiciousHeadersMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('suspicious_headers', $matchResult->source());
        $this->assertSame('Accept-Language', $matchResult->metadata()['missing']);
    }

    public function testCustomRequiredHeaders(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher(['X-Custom-Auth', 'X-Request-ID']);

        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-Custom-Auth', 'token');
        // Missing X-Request-ID

        $matchResult = $suspiciousHeadersMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('X-Request-ID', $matchResult->metadata()['missing']);
    }

    public function testCustomHeadersAllPresent(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher(['X-Custom-Auth']);
        $serverRequest = (new ServerRequest('GET', '/'))
            ->withHeader('X-Custom-Auth', 'token');

        $this->assertFalse($suspiciousHeadersMatcher->match($serverRequest)->isMatch());
    }

    public function testFirstMissingHeaderIsReported(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher();
        // Completely bare request -- Accept should be reported first
        $serverRequest = new ServerRequest('GET', '/');

        $matchResult = $suspiciousHeadersMatcher->match($serverRequest);
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('Accept', $matchResult->metadata()['missing']);
    }

    public function testConfigSectionIntegration(): void
    {
        $config = new Config(new InMemoryCache());
        $blocklistSection = $config->blocklists->suspiciousHeaders();

        $this->assertCount(1, $config->blocklists->rules());
        $this->assertArrayHasKey('suspicious-headers', $config->blocklists->rules());
        $this->assertSame($config->blocklists, $blocklistSection); // fluent
    }

    public function testConfigSectionCustomName(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->suspiciousHeaders('header-check', ['Authorization']);

        $this->assertArrayHasKey('header-check', $config->blocklists->rules());
    }

}
