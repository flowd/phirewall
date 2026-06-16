<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The OWASP diagnostics header is a core feature: when enabled, a blocklist match
 * whose source is 'owasp' and that carries an 'owasp_rule_id' adds an
 * X-Phirewall-Owasp-Rule response header. It is driven entirely by the MatchResult
 * source-string convention, so it is exercised here with a stub matcher rather than
 * the (separately packaged) CoreRuleSet engine.
 */
final class BlocklistOwaspDiagnosticsHeaderTest extends TestCase
{
    /**
     * @return array{0: Config, 1: Firewall}
     */
    private function buildFirewall(): array
    {
        $matcher = new class () implements RequestMatcherInterface {
            public function match(ServerRequestInterface $serverRequest): MatchResult
            {
                return MatchResult::matched('owasp', ['owasp_rule_id' => 600001]);
            }
        };

        // Deliberately name the rule something OTHER than 'owasp': the header must
        // be driven by the MatchResult source ('owasp'), not by the rule name.
        $config = new Config(new InMemoryCache());
        $config->blocklists->addRule(new BlocklistRule('crs-engine', $matcher));

        return [$config, new Firewall($config)];
    }

    public function testDiagnosticsHeaderIsAbsentByDefault(): void
    {
        [, $firewall] = $this->buildFirewall();
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/admin'));

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertArrayNotHasKey('X-Phirewall-Owasp-Rule', $firewallResult->headers);
    }

    public function testDiagnosticsHeaderIsPresentWhenEnabled(): void
    {
        [$config, $firewall] = $this->buildFirewall();
        $config->enableOwaspDiagnosticsHeader(true);
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/admin'));

        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame('600001', $firewallResult->headers['X-Phirewall-Owasp-Rule'] ?? null);
    }
}
