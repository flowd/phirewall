<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Flowd\Phirewall\Config\FileIpBlocklistStore;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class FileIpBlocklistTest extends TestCase
{
    public function testStoreCreatesFileAndMatcherBlocksAppendedIp(): void
    {
        vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

        $config = new Config(new \Flowd\Phirewall\Store\InMemoryCache());
        $fileIpBlocklistStore = $config->blocklists->fileIp('file-blocklist', $file);

        // file is created lazily when writing
        $fileIpBlocklistStore->add('203.0.113.10');

        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($fileIpBlocklistStore->getFilePath());
        $serverRequest = new ServerRequest('GET', '/foo', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.10']);
        $matchResult = $fileIpBlocklistMatcher->match($serverRequest);

        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('ip_file_blocklist', $matchResult->source());
    }

    public function testStoreIsIdempotentAndSkipsComments(): void
    {
        vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static function () use (&$now): int {
            return $now;
        });
        $fileIpBlocklistStore->addAll(['#comment', '198.51.100.22', '198.51.100.22', ';note']);

        $contents = file_get_contents($file);
        $this->assertSame("198.51.100.22||1700000000\n", $contents);
    }

    public function testTtlExpiryPrunedAndMatcherSkipsExpiredEntries(): void
    {
        vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

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
    }

    public function testRewriteThrottlingAppendsWithinWindowAndRewritesAfterWindow(): void
    {
        $root = vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

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

        // The full-rewrite path swaps a temp file in via rename; none may linger.
        foreach ($root->getChildren() as $vfsStreamContent) {
            $this->assertStringNotContainsString('.tmp.', $vfsStreamContent->getName(), 'Atomic rewrite must not leave a temp file behind');
        }
    }

    /**
     * M3 — auto-created parent directories must drop from the legacy world-writable
     * 0777 to an owner-only 0700 so blocklist data is not exposed to co-tenants.
     */
    public function testStoreCreatesMissingDirectoryWithOwnerOnlyPermissions(): void
    {
        $root = vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/nested/deep/list.txt');

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static fn(): int => $now);

        $fileIpBlocklistStore->add('203.0.113.10');

        $this->assertTrue($root->hasChild('nested/deep'));
        $this->assertSame(0700, $root->getChild('nested/deep')->getPermissions());
    }

    /**
     * M6 — crash-safety: when the new content cannot be written, the live blocklist must
     * keep its previous entries. The legacy ftruncate(0)+fwrite would have already emptied
     * the file at this point. A read-only directory makes the temp-file creation fail,
     * standing in for an interrupted write on the full-rewrite path.
     */
    public function testFailedRewriteKeepsPreviousEntriesIntact(): void
    {
        $root = vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

        // A live entry plus an expired one; pruning the expired entry forces a rewrite.
        $original = "203.0.113.10||1700000000\n5.6.7.8|1700000050|1700000000\n";
        file_put_contents($file, $original);

        $now = 1_700_000_200; // past the expiry and outside the rewrite-throttle window
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static fn(): int => $now);

        // Read-only directory: the existing file can still be opened for writing,
        // but the sibling temp file cannot be created, so the rename never happens.
        $root->chmod(0500);

        $thrown = null;
        try {
            $fileIpBlocklistStore->pruneExpired();
        } catch (\RuntimeException $runtimeException) {
            $thrown = $runtimeException;
        } finally {
            $root->chmod(0700);
        }

        $this->assertInstanceOf(\RuntimeException::class, $thrown, 'A failed atomic write must surface as a RuntimeException');
        $this->assertSame($original, file_get_contents($file), 'A failed atomic write must not corrupt or empty the live blocklist');
    }

    /**
     * M6 — writers serialize on a dedicated, never-renamed sidecar lock file. The
     * full-rewrite path swaps the live file's inode via rename(), so the lock
     * cannot live on the live file; the sidecar must be created and the live
     * content stay correct.
     */
    public function testWritersSerializeOnSidecarLockFileAndPreserveContent(): void
    {
        $root = vfsStream::setup('blocklist', 0700);
        $file = vfsStream::url('blocklist/list.txt');

        $now = 1_700_000_000;
        $fileIpBlocklistStore = new FileIpBlocklistStore($file, now: static fn(): int => $now);

        $fileIpBlocklistStore->add('203.0.113.10');

        $this->assertTrue(
            $root->hasChild('list.txt.lock'),
            'A sidecar .lock file must be created so the lock survives the rename that swaps the live inode'
        );
        $this->assertStringContainsString('203.0.113.10', (string) file_get_contents($file));
    }
}
