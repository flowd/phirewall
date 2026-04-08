<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FileIpBlocklistMatcherTest extends TestCase
{
    public function testInitialMissingFileThrows(): void
    {
        $path = __DIR__ . '/non-existing-blocklist.txt';
        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($path);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

        $this->expectException(\RuntimeException::class);
        $fileIpBlocklistMatcher->match($serverRequest);
    }

    public function testSubsequentMissingFileKeepsLastKnownGoodState(): void
    {
        $path = sys_get_temp_dir() . '/phirewall-blocklist-' . uniqid('', true) . '.txt';
        file_put_contents($path, "1.2.3.4\n");

        try {
            $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($path, null, 0);
            $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
            $blocked = $fileIpBlocklistMatcher->match($serverRequest);
            $this->assertTrue($blocked->isMatch());

            // Remove file after initial successful load
            unlink($path);

            // Second match must not throw and should still use last known good state
            $stillBlocked = $fileIpBlocklistMatcher->match($serverRequest);
            $this->assertTrue($stillBlocked->isMatch());
        } finally {
            if (file_exists($path)) {
                @unlink($path);
            }
        }
    }

    public function testReloadIsThrottledByMinReloadInterval(): void
    {
        $path = sys_get_temp_dir() . '/phirewall-blocklist-' . uniqid('', true) . '.txt';
        file_put_contents($path, "1.2.3.4\n");

        try {
            $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($path, null, 5); // 5 seconds interval
            $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);

            // First match loads 1.2.3.4
            $this->assertTrue($fileIpBlocklistMatcher->match($serverRequest)->isMatch());

            // Update file to only contain 5.6.7.8 but keep mtime the same by writing quickly
            file_put_contents($path, "5.6.7.8\n");

            // Because reload attempts are throttled, a subsequent match shortly after
            // should still use the previous in-memory state.
            $stillBlocked = $fileIpBlocklistMatcher->match($serverRequest);
            $this->assertTrue($stillBlocked->isMatch());
        } finally {
            if (file_exists($path)) {
                @unlink($path);
            }
        }
    }

    public function testExpiredEntriesAreSkippedOnReload(): void
    {
        $path = sys_get_temp_dir() . '/phirewall-blocklist-' . uniqid('', true) . '.txt';
        $now = time();
        // 1.2.3.4 expired, 5.6.7.8 still valid
        file_put_contents($path, "1.2.3.4|" . ($now - 10) . "\n5.6.7.8|" . ($now + 3600) . "\n");

        try {
            $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($path, null, 0);
            $requestExpired = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '1.2.3.4']);
            $requestValid = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '5.6.7.8']);

            $expired = $fileIpBlocklistMatcher->match($requestExpired);
            $this->assertFalse($expired->isMatch());

            $valid = $fileIpBlocklistMatcher->match($requestValid);
            $this->assertTrue($valid->isMatch());
        } finally {
            if (file_exists($path)) {
                @unlink($path);
            }
        }
    }
}
