<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistStore;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FileIpBlocklistTest extends TestCase
{
    public function testStoreCreatesFileAndMatcherBlocksAppendedIp(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-blocklist-');
        $this->assertIsString($file);
        @unlink($file); // ensure fresh file for test

        $config = new Config(new \Flowd\Phirewall\Store\InMemoryCache());
        $fileIpBlocklistStore = $config->fileIpBlocklist('file-blocklist', $file);

        // file is created lazily when writing
        $fileIpBlocklistStore->add('203.0.113.10');

        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($fileIpBlocklistStore->getFilePath());
        $serverRequest = new ServerRequest('GET', '/foo', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
        $matchResult = $fileIpBlocklistMatcher->match($serverRequest);

        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('ip_file_blocklist', $matchResult->source());

        @unlink($file);
    }

    public function testStoreIsIdempotentAndSkipsComments(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-blocklist-');
        $this->assertIsString($file);
        @unlink($file);

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static function () use (&$now): int {
            return $now;
        });
        $fileIpBlocklistStore->addAll(['#comment', '198.51.100.22', '198.51.100.22', ';note']);

        $contents = file_get_contents($file);
        $this->assertSame("198.51.100.22||1700000000\n", $contents);

        @unlink($file);
    }

    public function testTtlExpiryPrunedAndMatcherSkipsExpiredEntries(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-blocklist-');
        $this->assertIsString($file);
        @unlink($file);

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static function () use (&$now): int {
            return $now;
        });

        $fileIpBlocklistStore->addWithTtl('203.0.113.50', 10);
        $this->assertSame("203.0.113.50|1700000010|1700000000\n", file_get_contents($file));

        // Advance past expiry and prune
        $now = 1_700_000_100;
        $fileIpBlocklistStore->pruneExpired();
        $this->assertSame('', file_get_contents($file));

        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($file);
        $serverRequest = new ServerRequest('GET', '/foo', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.50']);
        $this->assertFalse($fileIpBlocklistMatcher->match($serverRequest)->isMatch());

        @unlink($file);
    }

    public function testRewriteThrottlingAppendsWithinWindowAndRewritesAfterWindow(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-blocklist-');
        $this->assertIsString($file);
        @unlink($file);

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static function () use (&$now): int {
            return $now;
        });

        $fileIpBlocklistStore->add('203.0.113.10');
        $this->assertSame("203.0.113.10||1700000000\n", file_get_contents($file));

        // Within 60s window -> append instead of rewrite
        $fileIpBlocklistStore->addWithTtl('198.51.100.22', 10);
        $this->assertSame("203.0.113.10||1700000000\n198.51.100.22|1700000010|1700000000\n", file_get_contents($file));

        // Advance beyond throttle window; expired entry pruned and rewrite occurs
        $now = 1_700_000_061;
        $fileIpBlocklistStore->add('2001:db8::1');

        $expected = "203.0.113.10||1700000000\n198.51.100.22|1700000010|1700000000\n2001:db8::1||1700000061\n";
        $this->assertSame($expected, file_get_contents($file));

        @unlink($file);
    }
}
