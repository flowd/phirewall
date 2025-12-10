<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Pattern;

use Flowd\Phirewall\Pattern\FilePatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use PHPUnit\Framework\TestCase;

final class FilePatternBackendTest extends TestCase
{
    public function testConsumeParsesEntriesAndReturnsSnapshotWithVersion(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-pattern-');
        $this->assertIsString($file);
        @unlink($file);

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

        $kinds = array_map(static fn(PatternEntry $patternEntry): string => $patternEntry->kind, $patternSnapshot->entries);
        $this->assertContains(PatternKind::IP, $kinds);
        $this->assertContains(PatternKind::CIDR, $kinds);
        $this->assertContains(PatternKind::PATH_PREFIX, $kinds);
        $this->assertContains(PatternKind::HEADER_EXACT, $kinds);

        @unlink($file);
    }

    public function testAppendMergesAndPrunesExpired(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-pattern-');
        $this->assertIsString($file);
        @unlink($file);

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

        @unlink($file);
    }

    public function testIgnoresCommentsAndBlankLines(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'phirewall-pattern-');
        $this->assertIsString($file);
        @unlink($file);

        $filePatternBackend = new FilePatternBackend($file, now: static fn(): int => 1_700_000_000);

        file_put_contents($file, "#comment\n;note\n\n" . PatternKind::IP . "|203.0.113.77|||1700000000\n");

        $patternSnapshot = $filePatternBackend->consume();
        $this->assertCount(1, $patternSnapshot->entries);
        $this->assertSame('203.0.113.77', $patternSnapshot->entries[0]->value);

        @unlink($file);
    }
}
