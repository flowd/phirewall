<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Pattern;

use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class FilePatternBackendTest extends TestCase
{
    public function testConsumeParsesEntriesAndReturnsSnapshotWithVersion(): void
    {
        vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => $now);

        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10', addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::CIDR, '198.51.100.0/24', addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::PATH_PREFIX, '/admin', addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::HEADER_EXACT, 'bad-bot', target: 'User-Agent', addedAt: $now));

        $patternSnapshot = $filePatternBackend->consume();

        $this->assertSame($file, $patternSnapshot->source);
        $this->assertNotEmpty($patternSnapshot->version);
        $this->assertCount(4, $patternSnapshot->entries);

        $kinds = array_map(static fn(PatternEntry $patternEntry): PatternKind => $patternEntry->kind, $patternSnapshot->entries);
        $this->assertContains(PatternKind::IP, $kinds);
        $this->assertContains(PatternKind::CIDR, $kinds);
        $this->assertContains(PatternKind::PATH_PREFIX, $kinds);
        $this->assertContains(PatternKind::HEADER_EXACT, $kinds);
    }

    public function testAppendMergesAndPrunesExpired(): void
    {
        vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static function () use (&$now): int {
            return $now;
        });

        // Add with TTL and ensure it is pruned on subsequent read
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.50', expiresAt: $now + 10, addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.50', expiresAt: $now + 20, addedAt: $now + 5)); // merge extends expiry

        $now = 1_700_000_021; // advance past expiry
        $filePatternBackend->pruneExpired();

        $patternSnapshot = $filePatternBackend->consume();
        $this->assertCount(0, $patternSnapshot->entries, 'Expired entry should be pruned');
    }

    public function testIgnoresCommentsAndBlankLines(): void
    {
        vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => 1_700_000_000);

        file_put_contents($file, "#comment\n;note\n\n" . PatternKind::IP->value . "|203.0.113.77|||1700000000\n");

        $patternSnapshot = $filePatternBackend->consume();
        $this->assertCount(1, $patternSnapshot->entries);
        $this->assertSame('203.0.113.77', $patternSnapshot->entries[0]->value);
    }

    /**
     * M3 — auto-created parent directories must drop from the legacy world-writable
     * 0777 to an owner-only 0700 so pattern data is not exposed to co-tenants.
     */
    public function testAppendCreatesMissingDirectoryWithOwnerOnlyPermissions(): void
    {
        $root = vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/nested/deep/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => $now);

        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10', addedAt: $now));

        $this->assertTrue($root->hasChild('nested/deep'));
        $this->assertSame(0700, $root->getChild('nested/deep')->getPermissions());
    }

    /**
     * M6 — the full-rewrite path writes through a temp file and renames it onto the
     * target. After a rewrite the new content must be present and no temp artifact
     * may linger in the directory.
     */
    public function testPruneExpiredRewritesAtomicallyWithoutLeavingTempArtifacts(): void
    {
        $root = vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static function () use (&$now): int {
            return $now;
        });

        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10', addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.99', expiresAt: $now + 10, addedAt: $now));

        $now = 1_700_000_021; // second entry expires
        $filePatternBackend->pruneExpired();

        $contents = file_get_contents($file);
        $this->assertIsString($contents);
        $this->assertNotSame('', $contents, 'Surviving entries mean the file must never be left empty');
        $this->assertStringContainsString('203.0.113.10', $contents);
        $this->assertStringNotContainsString('203.0.113.99', $contents);

        foreach ($root->getChildren() as $vfsStreamContent) {
            $this->assertStringNotContainsString('.tmp.', $vfsStreamContent->getName(), 'Atomic rewrite must not leave a temp file behind');
        }
    }

    /**
     * M6 — crash-safety: if the new content cannot be written, the live file must keep
     * its previous content. The legacy ftruncate(0)+fwrite would have already emptied
     * the file at this point. A read-only directory makes the temp-file creation fail,
     * standing in for an interrupted write.
     */
    public function testFailedRewriteKeepsPreviousContentIntact(): void
    {
        $root = vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => $now);
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10', addedAt: $now));

        $original = file_get_contents($file);
        $this->assertIsString($original);
        $this->assertStringContainsString('203.0.113.10', $original);

        // Read-only directory: the existing file can still be opened for writing,
        // but the sibling temp file cannot be created, so the rename never happens.
        $root->chmod(0500);

        $thrown = null;
        try {
            $filePatternBackend->pruneExpired();
        } catch (\RuntimeException $runtimeException) {
            $thrown = $runtimeException;
        } finally {
            $root->chmod(0700);
        }

        $this->assertInstanceOf(\RuntimeException::class, $thrown, 'A failed atomic write must surface as a RuntimeException');
        $this->assertSame($original, file_get_contents($file), 'A failed atomic write must not corrupt or empty the live file');
    }

    /**
     * M6 — writers serialize on a dedicated, never-renamed sidecar lock file. The
     * atomic rewrite swaps the live file's inode, so the lock cannot live on the
     * live file; the sidecar must be created and the live content stay correct.
     */
    public function testWritersSerializeOnSidecarLockFileAndPreserveContent(): void
    {
        $root = vfsStream::setup('patterns', 0700);
        $file = vfsStream::url('patterns/patterns.txt');

        $now = 1_700_000_000;
        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => $now);

        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.10', addedAt: $now));
        $filePatternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.11', addedAt: $now));

        $this->assertTrue(
            $root->hasChild('patterns.txt.lock'),
            'A sidecar .lock file must be created so the lock survives the rename that swaps the live inode'
        );

        $patternSnapshot = $filePatternBackend->consume();
        $values = array_map(static fn(PatternEntry $patternEntry): string => $patternEntry->value, $patternSnapshot->entries);
        $this->assertContains('203.0.113.10', $values);
        $this->assertContains('203.0.113.11', $values);
    }
}
