<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetPmFromFileTest extends TestCase
{
    public function testPmFromFileHappyPathAndCaseInsensitive(): void
    {
        $dir = sys_get_temp_dir() . '/phirewall_pmfromfile_' . bin2hex(random_bytes(4));
        mkdir($dir);
        $file = $dir . '/phrases.txt';
        // Include comments, blanks, mixed case, and a multi-token comma line
        $content = <<<'TXT'
# comment line

admin
SeCrEt
alpha, beta ,  gamma
TXT;
        file_put_contents($file, $content);

        try {
            $rulesText = 'SecRule REQUEST_URI "@pmFromFile ' . str_replace('"', '\\"', $file) . '" "id:730001,phase:2,deny,msg:\'PM file\'"';
            $set = SecRuleLoader::fromString($rulesText);
            $this->assertContains(730001, $set->ids(), 'Rule id should be loaded');
            $rule = $set->getRule(730001);
            $this->assertNotNull($rule);
            $this->assertTrue($set->isEnabled(730001));
            $this->assertSame('@pmfromfile', strtolower($rule->operator));
            $this->assertSame($file, $rule->operatorArgument);
            $this->assertContains('REQUEST_URI', $rule->variables);

            // Matches any phrase (case-insensitive)
            $serverRequest = new ServerRequest('GET', '/admin');
            $this->assertTrue($rule->matches($serverRequest));
            $this->assertSame(730001, $set->match($serverRequest));
            $this->assertSame(730001, $set->match(new ServerRequest('GET', '/SECRET/path')));
            $this->assertSame(730001, $set->match(new ServerRequest('GET', '/one/alpha-two')));
            $this->assertSame(730001, $set->match(new ServerRequest('GET', '/beta')));
            $this->assertSame(730001, $set->match(new ServerRequest('GET', '/GAMMA')));

            // Non-matching
            $this->assertNull($set->match(new ServerRequest('GET', '/nohit')));
        } finally {
            @unlink($file);
            @rmdir($dir);
        }
    }

    public function testPmFromFileMissingFileIsSafeNoMatch(): void
    {
        $missing = sys_get_temp_dir() . '/phirewall_missing_' . bin2hex(random_bytes(4)) . '.txt';
        $rulesText = 'SecRule REQUEST_URI "@pmFromFile ' . $missing . '" "id:730002,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $this->assertNull($coreRuleSet->match(new ServerRequest('GET', '/anything')));
    }

    public function testPmFromFileRespectsPhraseCap(): void
    {
        $dir = sys_get_temp_dir() . '/phirewall_pmfromfile_cap_' . bin2hex(random_bytes(4));
        mkdir($dir);
        $file = $dir . '/many.txt';
        // Generate 5005 phrases: p0..p5004; the cap is 5000 in CoreRule
        $buf = '';
        for ($i = 0; $i < 5005; ++$i) {
            $buf .= 'p' . $i . "\n";
        }

        // A phrase beyond cap to ensure it does not match
        $buf .= "beyond-cap\n";
        file_put_contents($file, $buf);

        try {
            $rulesText = 'SecRule REQUEST_URI "@pmFromFile ' . str_replace('"', '\\"', $file) . '" "id:730003,phase:2,deny"';
            $set = SecRuleLoader::fromString($rulesText);

            // Should match an early phrase (within cap)
            $this->assertSame(730003, $set->match(new ServerRequest('GET', '/p10')));
            // Should not match phrase expected beyond cap (best-effort check)
            $this->assertNull($set->match(new ServerRequest('GET', '/beyond-cap')));
        } finally {
            @unlink($file);
            @rmdir($dir);
        }
    }
}
