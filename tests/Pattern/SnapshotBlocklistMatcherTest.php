<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Pattern;

use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class SnapshotBlocklistMatcherTest extends TestCase
{
    public function testMatchesIpCidrAndPathAndHeaderRegex(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-pattern-');
        $this->assertIsString($file);
        @unlink($file);

        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => 1_700_000_000);
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10'));
        $filePatternBackend->append(new PatternEntry(PatternKind::CIDR, '198.51.100.0/24'));
        $filePatternBackend->append(new PatternEntry(PatternKind::PATH_PREFIX, '/secret'));
        $filePatternBackend->append(new PatternEntry(PatternKind::HEADER_REGEX, '/curl|bot/i', target: 'User-Agent'));

        $snapshotBlocklistMatcher = new SnapshotBlocklistMatcher($filePatternBackend);

        $ipRequest = new ServerRequest('GET', '/any', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
        $this->assertTrue($snapshotBlocklistMatcher->match($ipRequest)->isMatch(), 'Exact IP should match');

        $cidrRequest = new ServerRequest('GET', '/any', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $this->assertTrue($snapshotBlocklistMatcher->match($cidrRequest)->isMatch(), 'CIDR should match');

        $pathRequest = new ServerRequest('GET', '/secret/data', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
        $this->assertTrue($snapshotBlocklistMatcher->match($pathRequest)->isMatch(), 'Path prefix should match');

        $headerRequest = (new ServerRequest('GET', '/any', ['User-Agent' => 'curl/8.0.0'], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']));
        $this->assertTrue($snapshotBlocklistMatcher->match($headerRequest)->isMatch(), 'Header regex should match');

        @unlink($file);
    }

    public function testSkipsExpiredAndIgnoresInvalidRegex(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-pattern-');
        $this->assertIsString($file);
        @unlink($file);

        $now = 1_700_000_000;
        $backend = new FilePatternBackend($file, now: static fn(): int => $now);
        $backend->append(new PatternEntry(PatternKind::IP, '203.0.113.20', expiresAt: $now + 5));
        $backend->append(new PatternEntry(PatternKind::REQUEST_REGEX, '/[invalid/', addedAt: $now)); // compile fails

        $matcher = new SnapshotBlocklistMatcher($backend);

        $request = new ServerRequest('GET', '/any', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.20']);
        $this->assertTrue($matcher->match($request)->isMatch(), 'Should match before expiry');

        $now = 1_700_000_006; // advance past expiry
        $backend = new FilePatternBackend($file, now: static fn(): int => $now); // reload backend with same file
        $matcher = new SnapshotBlocklistMatcher($backend);

        $this->assertFalse($matcher->match($request)->isMatch(), 'Expired entry should be ignored');

        // Ensure invalid regex pattern does not throw and does not match
        $headerRequest = new ServerRequest('GET', '/any', ['X-Test' => 'value'], null, '1.1', ['REMOTE_ADDR' => '198.51.100.10']);
        $this->assertFalse($matcher->match($headerRequest)->isMatch());

        @unlink($file);
    }
}
