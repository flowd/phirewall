<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Pattern;

use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use PHPUnit\Framework\TestCase;

final class InMemoryPatternBackendTest extends TestCase
{
    private int $now = 1000000;

    private function clock(): callable
    {
        return fn(): int => $this->now;
    }

    public function testEmptyBackend(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $this->assertSame(0, $inMemoryPatternBackend->count());
        $this->assertSame([], $inMemoryPatternBackend->consume()->entries);
    }

    public function testInitialEntries(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([
            new PatternEntry(PatternKind::IP, '1.2.3.4'),
            new PatternEntry(PatternKind::CIDR, '10.0.0.0/8'),
        ], $this->clock());
        $this->assertSame(2, $inMemoryPatternBackend->count());
        $this->assertCount(2, $inMemoryPatternBackend->consume()->entries);
    }

    public function testAppendAddsEntry(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '5.6.7.8'));
        $this->assertSame(1, $inMemoryPatternBackend->count());
        $this->assertSame('5.6.7.8', $inMemoryPatternBackend->consume()->entries[0]->value);
    }

    public function testAppendSetsAddedAtWhenNull(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1'));
        $this->assertSame($this->now, $inMemoryPatternBackend->consume()->entries[0]->addedAt);
    }

    public function testAppendPreservesExplicitAddedAt(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', addedAt: 42));
        $this->assertSame(42, $inMemoryPatternBackend->consume()->entries[0]->addedAt);
    }

    public function testDuplicateEntryIsMerged(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 2000000));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.2.3.4', expiresAt: 3000000));
        $this->assertSame(1, $inMemoryPatternBackend->count());
        $this->assertSame(3000000, $inMemoryPatternBackend->consume()->entries[0]->expiresAt);
    }

    public function testMergeKeepsLaterExpiry(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: 9000000));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: 5000000));
        $this->assertSame(9000000, $inMemoryPatternBackend->consume()->entries[0]->expiresAt);
    }

    public function testDifferentKindsSameValueNotMerged(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '10.0.0.1'));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::CIDR, '10.0.0.1'));
        $this->assertSame(2, $inMemoryPatternBackend->count());
    }

    public function testDifferentTargetsNotMerged(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::HEADER_EXACT, 'bad', target: 'User-Agent'));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::HEADER_EXACT, 'bad', target: 'Referer'));
        $this->assertSame(2, $inMemoryPatternBackend->count());
    }

    public function testConsumeFiltersExpiredEntries(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: $this->now - 1));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '2.2.2.2', expiresAt: $this->now + 3600));

        $patternSnapshot = $inMemoryPatternBackend->consume();
        $this->assertCount(1, $patternSnapshot->entries);
        $this->assertSame('2.2.2.2', $patternSnapshot->entries[0]->value);
    }

    public function testConsumeFiltersExactlyExpiredEntry(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: $this->now));
        $this->assertCount(0, $inMemoryPatternBackend->consume()->entries);
    }

    public function testNullExpiresAtNeverExpires(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1'));

        $this->now = 9999999999;
        $this->assertCount(1, $inMemoryPatternBackend->consume()->entries);
    }

    public function testPruneExpiredRemovesEntries(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: $this->now + 10));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '2.2.2.2', expiresAt: $this->now + 3600));
        $this->now += 100;
        $inMemoryPatternBackend->pruneExpired();
        $this->assertSame(1, $inMemoryPatternBackend->count());
        $this->assertSame('2.2.2.2', $inMemoryPatternBackend->consume()->entries[0]->value);
    }

    public function testPruneNoChangeDoesNotIncrementVersion(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: $this->now + 9999));

        $v1 = $inMemoryPatternBackend->consume()->version;
        $inMemoryPatternBackend->pruneExpired();
        $this->assertSame($v1, $inMemoryPatternBackend->consume()->version);
    }

    public function testPruneExpiredIncrementsVersion(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1', expiresAt: $this->now + 1));

        $v1 = $inMemoryPatternBackend->consume()->version;
        $this->now += 10;
        $inMemoryPatternBackend->pruneExpired();
        $this->assertGreaterThan($v1, $inMemoryPatternBackend->consume()->version);
    }

    public function testVersionIncrementsOnAppend(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $v0 = $inMemoryPatternBackend->consume()->version;
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1'));
        $v1 = $inMemoryPatternBackend->consume()->version;
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '2.2.2.2'));
        $this->assertGreaterThan($v0, $v1);
        $this->assertGreaterThan($v1, $inMemoryPatternBackend->consume()->version);
    }

    public function testVersionIncrementsOnClear(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([new PatternEntry(PatternKind::IP, '1.1.1.1')], $this->clock());
        $v1 = $inMemoryPatternBackend->consume()->version;
        $inMemoryPatternBackend->clear();
        $this->assertGreaterThan($v1, $inMemoryPatternBackend->consume()->version);
    }

    public function testClearRemovesAllEntries(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([
            new PatternEntry(PatternKind::IP, '1.1.1.1'),
            new PatternEntry(PatternKind::IP, '2.2.2.2'),
        ], $this->clock());
        $inMemoryPatternBackend->clear();
        $this->assertSame(0, $inMemoryPatternBackend->count());
        $this->assertSame([], $inMemoryPatternBackend->consume()->entries);
    }

    public function testType(): void
    {
        $this->assertSame('memory', (new InMemoryPatternBackend())->type());
    }

    public function testCapabilities(): void
    {
        $caps = (new InMemoryPatternBackend())->capabilities();
        $this->assertSame(PatternKind::all(), $caps['kinds']);
        $this->assertSame(PatternBackendInterface::MAX_ENTRIES_DEFAULT, $caps['max_entries']);
    }

    public function testSnapshotSource(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $this->assertSame('memory', $inMemoryPatternBackend->consume()->source);
    }

    public function testEntriesPreserveInsertionOrder(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '3.3.3.3'));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '1.1.1.1'));
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, '2.2.2.2'));

        $values = array_map(fn($e): string => $e->value, $inMemoryPatternBackend->consume()->entries);
        $this->assertSame(['3.3.3.3', '1.1.1.1', '2.2.2.2'], $values);
    }

    public function testMaxEntriesThrowsOnOverflow(): void
    {
        $inMemoryPatternBackend = new InMemoryPatternBackend([], $this->clock());
        $reflectionClass = new \ReflectionClass($inMemoryPatternBackend);
        $reflectionProperty = $reflectionClass->getProperty('entries');
        $orderProp = $reflectionClass->getProperty('order');

        $fakeEntries = [];
        $fakeOrder = [];
        for ($i = 0; $i < PatternBackendInterface::MAX_ENTRIES_DEFAULT; ++$i) {
            $key = 'ip::fake-' . $i;
            $fakeEntries[$key] = new PatternEntry(PatternKind::IP, 'fake-' . $i);
            $fakeOrder[] = $key;
        }

        $reflectionProperty->setValue($inMemoryPatternBackend, $fakeEntries);
        $orderProp->setValue($inMemoryPatternBackend, $fakeOrder);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/exceeds maximum entries/');
        $inMemoryPatternBackend->append(new PatternEntry(PatternKind::IP, 'overflow'));
    }
}
