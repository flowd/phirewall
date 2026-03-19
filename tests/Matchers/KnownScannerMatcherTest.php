<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Matchers\KnownScannerMatcher;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KnownScannerMatcherTest extends TestCase
{
    private function makeRequest(string $userAgent): ServerRequest
    {
        return new ServerRequest('GET', '/', ['User-Agent' => $userAgent]);
    }

    public function testMatchesBuiltInScanners(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher();

        $scannerUAs = [
            'sqlmap/1.7.8#stable (https://sqlmap.org)',
            'Mozilla/5.0 (compatible; Nikto/2.1.6)',
            'Nmap Scripting Engine; https://nmap.org/book/nse.html',
            'masscan/1.0 (https://github.com/robertdavidgraham/masscan)',
            'ZmEu',
            'acunetix-product',
            'Nessus SOAP v0.0.1',
            'OpenVAS',
            'w3af.sourceforge.net',
            'DirBuster-1.0-RC1',
            'gobuster/3.1.0',
            'WFuzz/2.4',
            'THC-Hydra',
            'Medusa v2.2',
            'BurpSuite',
            'Burp Suite Pro',
            'skipfish/2.10b',
            'WhatWeb/0.5.5',
            'Metasploit',
            'nuclei/3.0.0',
            'ffuf/1.5.0',
            'Feroxbuster',
            'WPScan',
        ];

        foreach ($scannerUAs as $scannerUA) {
            $result = $knownScannerMatcher->match($this->makeRequest($scannerUA));
            $this->assertTrue($result->isMatch(), 'Expected match for UA: ' . $scannerUA);
            $this->assertSame('known_scanner', $result->source());
        }
    }

    public function testCaseInsensitiveMatching(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher();

        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('SQLMAP/1.0'))->isMatch());
        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('Nikto'))->isMatch());
        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('NUCLEI/2.0'))->isMatch());
    }

    public function testDoesNotMatchLegitimateUserAgents(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher();

        $legit = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'curl/7.85.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'python-requests/2.28.0',
        ];

        foreach ($legit as $ua) {
            $this->assertFalse($knownScannerMatcher->match($this->makeRequest($ua))->isMatch(), 'Should not match: ' . $ua);
        }
    }

    public function testEmptyUserAgentDoesNotMatch(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher();
        $serverRequest = new ServerRequest('GET', '/');
        $this->assertFalse($knownScannerMatcher->match($serverRequest)->isMatch());
    }

    public function testCustomPatternsReplaceDefaults(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher(['my-custom-scanner', 'evil-bot']);

        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('my-custom-scanner/1.0'))->isMatch());
        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('Evil-Bot v2'))->isMatch());
        // Defaults are replaced, not merged
        $this->assertFalse($knownScannerMatcher->match($this->makeRequest('sqlmap/1.0'))->isMatch());
    }

    public function testExtendDefaultPatterns(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher([...KnownScannerMatcher::DEFAULT_PATTERNS, 'my-custom-scanner']);

        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('my-custom-scanner/1.0'))->isMatch());
        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('sqlmap/1.0'))->isMatch()); // defaults still work
    }

    public function testIntegrationViaConfig(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklists->knownScanners();

        $firewall = new Firewall($config);

        $blocked = new ServerRequest('GET', '/', ['User-Agent' => 'sqlmap/1.7']);
        $firewallResult = $firewall->decide($blocked);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);

        $allowed = new ServerRequest('GET', '/', ['User-Agent' => 'Mozilla/5.0']);
        $this->assertTrue($firewall->decide($allowed)->isPass());
    }

    public function testCustomRuleName(): void
    {
        $inMemoryCache = new InMemoryCache();
        $config = new Config($inMemoryCache);
        $config->blocklists->knownScanners('my-scanner-rule');

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', ['User-Agent' => 'nikto']);
        $firewallResult = $firewall->decide($serverRequest);

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('my-scanner-rule', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testEmptyPatternThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new KnownScannerMatcher(['sqlmap', '', 'nikto']);
    }

    public function testWhitespaceOnlyPatternThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new KnownScannerMatcher(['  ']);
    }

    public function testPatternsTrimmed(): void
    {
        $knownScannerMatcher = new KnownScannerMatcher(['  sqlmap  ']);
        $this->assertTrue($knownScannerMatcher->match($this->makeRequest('sqlmap/1.0'))->isMatch());
    }
}
