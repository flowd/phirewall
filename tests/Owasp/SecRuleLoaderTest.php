<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class SecRuleLoaderTest extends TestCase
{
    public function testFromStringParsesMultilineSecRuleAndMatches(): void
    {
        $text = <<<'RULE'
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)<\?(?:[^x]|x(?:[^m]|m(?:[^l]|l(?:[^\s\x0b]|[\s\x0b]+[^a-z]|$)))|$|php)|\[[/\x5c]?php\]" \
    "id:933100,\
    phase:2,\
    block,\
    capture,\
    t:none,\
    msg:'PHP Injection Attack: PHP Open Tag Found',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-injection-php',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-PHP',\
    tag:'capec/1000/152/242',\
    ver:'OWASP_CRS/4.21.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
RULE;
        $coreRuleSet = SecRuleLoader::fromString($text);
        $req = new ServerRequest('GET', '/');
        $req = $req->withCookieParams(['a' => '<?php echo 1;']);
        $this->assertSame(933100, $coreRuleSet->match($req));
    }

    public function testFromFileParsesMultilineSecRuleAndContainsId(): void
    {
        $root = dirname(__DIR__, 2);
        $path = $root . '/examples/owasp_crs_basic/REQUEST-933-APPLICATION-ATTACK-PHP.conf';
        $this->assertFileExists($path);
        $coreRuleSet = SecRuleLoader::fromFile($path);
        $this->assertContains(933100, $coreRuleSet->ids(), 'Expected multiline rule 933100 to be parsed from file');

        // And it should match request with PHP open tag in cookies
        $req = new ServerRequest('GET', '/');
        $req = $req->withCookieParams(['sess' => 'xx<?php yy']);
        $this->assertSame(933100, $coreRuleSet->match($req));
    }

    public function testFromStringWithReportCountsParsedAndSkipped(): void
    {
        $text = <<<'TXT'
# comment
SecRule REQUEST_URI "@contains admin" "id:700001,phase:2,deny"
invalid line
SecRule REQUEST_METHOD "@streq POST" "id:700002,phase:2,deny"
TXT;
        $result = SecRuleLoader::fromStringWithReport($text);
        $this->assertSame(2, $result['parsed']);
        // Comment lines are dropped during logical line building; only the truly invalid line is counted as skipped
        $this->assertSame(1, $result['skipped']);

        $rules = $result['rules'];
        $this->assertNotNull($rules->match(new ServerRequest('GET', '/admin')));
        $this->assertNotNull($rules->match(new ServerRequest('POST', '/x')));
    }

    public function testFromFilesLoadsConcatenatedFiles(): void
    {
        $dir = sys_get_temp_dir() . '/phirewall_test_' . bin2hex(random_bytes(4));
        mkdir($dir);
        try {
            $f1 = $dir . '/a.conf';
            $f2 = $dir . '/b.conf';
            file_put_contents($f1, "SecRule REQUEST_URI \"@contains a\" \"id:710001,phase:2,deny\"\n");
            file_put_contents($f2, "SecRule REQUEST_URI \"@contains b\" \"id:710002,phase:2,deny\"\n");

            $set = SecRuleLoader::fromFiles([$f1, $f2]);
            $this->assertSame(710001, $set->match(new ServerRequest('GET', '/a')));
            $this->assertSame(710002, $set->match(new ServerRequest('GET', '/b')));
        } finally {
            @unlink($dir . '/a.conf');
            @unlink($dir . '/b.conf');
            @rmdir($dir);
        }
    }

    public function testFromFilesThrowsOnMissingFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecRuleLoader::fromFiles(['/not/exist/file.conf']);
    }

    public function testFromDirectoryLoadsSortedAndRespectsFilter(): void
    {
        $dir = sys_get_temp_dir() . '/phirewall_test_' . bin2hex(random_bytes(4));
        mkdir($dir);
        try {
            file_put_contents($dir . '/2.conf', "SecRule REQUEST_URI \"@contains two\" \"id:720002,phase:2,deny\"\n");
            file_put_contents($dir . '/1.conf', "SecRule REQUEST_URI \"@contains one\" \"id:720001,phase:2,deny\"\n");
            file_put_contents($dir . '/skip.txt', "SecRule REQUEST_URI \"@contains skip\" \"id:720999,phase:2,deny\"\n");

            $filter = static fn(string $path): bool => str_ends_with($path, '.conf');
            $set = SecRuleLoader::fromDirectory($dir, $filter);

            // Sorted order means rule ids 720001 then 720002 are present; skip.txt ignored
            $this->assertSame(720001, $set->match(new ServerRequest('GET', '/one')));
            $this->assertSame(720002, $set->match(new ServerRequest('GET', '/two')));
            $this->assertNull($set->match(new ServerRequest('GET', '/skip')));
        } finally {
            @unlink($dir . '/1.conf');
            @unlink($dir . '/2.conf');
            @unlink($dir . '/skip.txt');
            @rmdir($dir);
        }
    }
}
