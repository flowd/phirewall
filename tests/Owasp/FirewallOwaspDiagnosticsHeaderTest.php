<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallOwaspDiagnosticsHeaderTest extends TestCase
{
    /**
     * @return array{0: Config, 1: Firewall}
     */
    private function buildFirewallWithOwasp(): array
    {
        $rulesText = "SecRule REQUEST_URI \"@rx ^/admin\\b\" \"id:600001,phase:2,deny,msg:'Block admin path'\"";
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $config = new Config(new InMemoryCache());
        $config->owaspBlocklist('owasp', $coreRuleSet);
        return [$config, new Firewall($config)];
    }

    public function testDiagnosticsHeaderIsAbsentByDefault(): void
    {
        [$config, $firewall] = $this->buildFirewallWithOwasp();
        $serverRequest = new ServerRequest('GET', '/admin');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertArrayNotHasKey('X-Phirewall-Owasp-Rule', $firewallResult->headers);
    }

    public function testDiagnosticsHeaderIsPresentWhenEnabled(): void
    {
        [$config, $firewall] = $this->buildFirewallWithOwasp();
        // enable header toggle
        $config->enableOwaspDiagnosticsHeader(true);
        $serverRequest = new ServerRequest('GET', '/admin');
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('600001', $firewallResult->headers['X-Phirewall-Owasp-Rule'] ?? null);
    }
}
