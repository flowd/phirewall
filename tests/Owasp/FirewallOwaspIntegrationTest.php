<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FirewallOwaspIntegrationTest extends TestCase
{
    public function testOwaspBlocklistBlocksAndCanDisableRule(): void
    {
        $rulesText = "SecRule REQUEST_URI \"@rx ^/admin\b\" \"id:100010,phase:2,deny,msg:'Block admin path'\"";
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $config = new Config(new InMemoryCache());
        $config->owaspBlocklist('owasp', $coreRuleSet);

        $firewall = new Firewall($config);

        // Matches rule -> blocked
        $req1 = new ServerRequest('GET', '/admin');
        $firewallResult = $firewall->decide($req1);
        $this->assertTrue($firewallResult->isBlocked());
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('blocklist', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('owasp', $firewallResult->headers['X-Phirewall-Matched'] ?? '');

        // Disable rule -> pass
        $coreRuleSet->disable(100010);
        $req2 = new ServerRequest('GET', '/admin');
        $res2 = $firewall->decide($req2);
        $this->assertTrue($res2->isPass());
    }
}
