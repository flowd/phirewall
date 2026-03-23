<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ApacheHtaccessAdapterTest extends TestCase
{
    private string $tmpDir = '';

    private string $htaccess = '';

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/phirewall_htaccess_test_' . bin2hex(random_bytes(4));
        mkdir($this->tmpDir, 0755, true);
        $this->htaccess = $this->tmpDir . '/.htaccess';
    }

    protected function tearDown(): void
    {
        // Clean up all files including dotfiles (glob '*' skips dotfiles)
        $patterns = [
            $this->tmpDir . '/*',
            $this->tmpDir . '/.*',
        ];

        foreach ($patterns as $pattern) {
            $files = glob($pattern) ?: [];
            foreach ($files as $file) {
                if (is_file($file)) {
                    @unlink($file);
                }
            }
        }

        if (is_dir($this->tmpDir)) {
            @rmdir($this->tmpDir);
        }
    }

    // ─── Single IP block ─────────────────────────────────────────────

    public function testBlockSingleIpWritesCorrectDenyDirective(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.10');

        $content = $this->readHtaccess();
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('Require not ip 203.0.113.10', $content);
        self::assertStringContainsString('# END Phirewall', $content);
    }

    public function testBlockSingleIpIsIdempotent(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.10');
        $first = $this->readHtaccess();

        $adapter->blockIp('203.0.113.10');
        $second = $this->readHtaccess();

        self::assertSame($first, $second, 'Blocking the same IP twice must not change the file');
    }

    // ─── IPv6 ────────────────────────────────────────────────────────

    public function testBlockIpv6Address(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('2001:db8::1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 2001:db8::1', $content);
    }

    public function testIpv6NormalizationPreventsExpandedDuplicates(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('2001:0db8:0000:0000:0000:0000:0000:0001');
        $adapter->blockIp('2001:db8::1');

        $content = $this->readHtaccess();
        // Should appear only once in compressed form
        self::assertSame(
            1,
            substr_count($content, 'Require not ip 2001:db8::1'),
            'Expanded and compressed IPv6 forms should be deduplicated'
        );
    }

    // ─── Removing a ban ──────────────────────────────────────────────

    public function testUnblockIpRemovesDirective(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('198.51.100.5');
        self::assertTrue($adapter->isBlocked('198.51.100.5'));

        $adapter->unblockIp('198.51.100.5');
        self::assertFalse($adapter->isBlocked('198.51.100.5'));
        self::assertStringNotContainsString('Require not ip 198.51.100.5', $this->readHtaccess());
    }

    public function testUnblockNonExistentIpIsNoOp(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $before = $this->readHtaccess();

        $adapter->unblockIp('203.0.113.99');
        $after = $this->readHtaccess();

        self::assertSame($before, $after, 'Unblocking a non-existent IP should not modify the file');
    }

    // ─── Multiple bans ───────────────────────────────────────────────

    public function testMultipleBansWriteMultipleDirectives(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');
        $adapter->blockIp('2001:db8::ff');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringContainsString('Require not ip 203.0.113.2', $content);
        self::assertStringContainsString('Require not ip 2001:db8::ff', $content);
    }

    public function testMultipleBansPreserveInsertionOrder(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.3');
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');

        $content = $this->readHtaccess();
        $pos1 = strpos($content, 'Require not ip 203.0.113.3');
        $pos2 = strpos($content, 'Require not ip 203.0.113.1');
        $pos3 = strpos($content, 'Require not ip 203.0.113.2');

        self::assertNotFalse($pos1);
        self::assertNotFalse($pos2);
        self::assertNotFalse($pos3);
        self::assertLessThan($pos2, $pos1, 'First blocked IP should appear before second');
        self::assertLessThan($pos3, $pos2, 'Second blocked IP should appear before third');
    }

    // ─── blockMany / unblockMany ─────────────────────────────────────

    public function testBlockManyAddsAllIpsAtomically(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany(['203.0.113.10', '203.0.113.11', '2001:db8::2']);

        self::assertTrue($adapter->isBlocked('203.0.113.10'));
        self::assertTrue($adapter->isBlocked('203.0.113.11'));
        self::assertTrue($adapter->isBlocked('2001:db8::2'));
    }

    public function testBlockManyWithDuplicatesDeduplicates(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany(['203.0.113.10', '203.0.113.10', '203.0.113.10']);

        $content = $this->readHtaccess();
        self::assertSame(1, substr_count($content, 'Require not ip 203.0.113.10'));
    }

    public function testBlockManyWithEmptyArrayIsNoOp(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany([]);

        self::assertFileDoesNotExist($this->htaccess);
    }

    public function testBlockManyWithInvalidIpIsAllOrNothing(): void
    {
        file_put_contents($this->htaccess, "# Prelude\n");
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        try {
            $adapter->blockMany(['203.0.113.10', 'not_an_ip']);
            self::fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException) {
            // expected
        }

        $content = $this->readHtaccess();
        self::assertStringNotContainsString('# BEGIN Phirewall', $content);
        self::assertStringNotContainsString('Require not ip', $content);
    }

    public function testUnblockManyRemovesMultipleIps(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany(['203.0.113.1', '203.0.113.2', '203.0.113.3']);

        $adapter->unblockMany(['203.0.113.1', '203.0.113.3']);

        self::assertFalse($adapter->isBlocked('203.0.113.1'));
        self::assertTrue($adapter->isBlocked('203.0.113.2'));
        self::assertFalse($adapter->isBlocked('203.0.113.3'));
    }

    public function testUnblockManyWithEmptyArrayIsNoOp(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $before = $this->readHtaccess();

        $adapter->unblockMany([]);
        $after = $this->readHtaccess();

        self::assertSame($before, $after);
    }

    public function testUnblockManyWithInvalidIpThrows(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $this->expectException(InvalidArgumentException::class);
        $adapter->unblockMany(['bad_ip']);
    }

    // ─── File creation when .htaccess doesn't exist ──────────────────

    public function testCreatesHtaccessFileWhenItDoesNotExist(): void
    {
        self::assertFileDoesNotExist($this->htaccess);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.50');

        self::assertFileExists($this->htaccess);
        $content = $this->readHtaccess();
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('Require not ip 203.0.113.50', $content);
        self::assertStringContainsString('# END Phirewall', $content);
    }

    public function testIsBlockedReturnsFalseWhenFileDoesNotExist(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        self::assertFalse($adapter->isBlocked('203.0.113.1'));
    }

    // ─── Preserving existing .htaccess content ───────────────────────

    public function testPreservesExistingContentBeforeMarkers(): void
    {
        $preamble = "Options -Indexes\nRewriteEngine On\nRewriteRule ^index\\.html$ / [R=301,L]\n";
        file_put_contents($this->htaccess, $preamble);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.42');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Options -Indexes', $content);
        self::assertStringContainsString('RewriteEngine On', $content);
        self::assertStringContainsString('RewriteRule', $content);
        self::assertStringContainsString('Require not ip 203.0.113.42', $content);

        // Preamble should appear before the managed section
        $preamblePos = strpos($content, 'Options -Indexes');
        $beginPos = strpos($content, '# BEGIN Phirewall');
        self::assertNotFalse($preamblePos);
        self::assertNotFalse($beginPos);
        self::assertLessThan($beginPos, $preamblePos);
    }

    public function testPreservesExistingContentAfterMarkers(): void
    {
        $initial = "# Before\n\n# BEGIN Phirewall\nRequire not ip 203.0.113.1\n# END Phirewall\n\n# After section\nErrorDocument 404 /404.html\n";
        file_put_contents($this->htaccess, $initial);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.2');

        $content = $this->readHtaccess();
        self::assertStringContainsString('# Before', $content);
        self::assertStringContainsString('ErrorDocument 404 /404.html', $content);
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringContainsString('Require not ip 203.0.113.2', $content);

        // After content should appear after the managed section
        $endPos = strpos($content, '# END Phirewall');
        $afterPos = strpos($content, 'ErrorDocument 404');
        self::assertNotFalse($endPos);
        self::assertNotFalse($afterPos);
        self::assertLessThan($afterPos, $endPos);
    }

    public function testPreservesContentBeforeAndAfterManagedSection(): void
    {
        $before = "# Custom before\nOptions +FollowSymLinks\n";
        $after = "\n# Custom after\nErrorDocument 500 /500.html\n";
        $initial = $before
            . "\n# BEGIN Phirewall\nRequire not ip 10.0.0.1\n# END Phirewall"
            . $after;
        file_put_contents($this->htaccess, $initial);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->unblockIp('10.0.0.1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Options +FollowSymLinks', $content);
        self::assertStringContainsString('ErrorDocument 500 /500.html', $content);
        self::assertStringNotContainsString('Require not ip 10.0.0.1', $content);
    }

    // ─── Template / marker replacement ───────────────────────────────

    public function testManagedSectionReplacesOnlyBetweenMarkers(): void
    {
        $initial = "# Before\n\n# BEGIN Phirewall\nRequire not ip 203.0.113.1\n# END Phirewall\n\n# After\n";
        file_put_contents($this->htaccess, $initial);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->unblockIp('203.0.113.1');
        $adapter->blockIp('198.51.100.1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 198.51.100.1', $content);
        self::assertStringNotContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('# END Phirewall', $content);
        // Only one pair of markers
        self::assertSame(1, substr_count($content, '# BEGIN Phirewall'));
        self::assertSame(1, substr_count($content, '# END Phirewall'));
    }

    public function testBlockDoesNotDuplicateMarkers(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');
        $adapter->blockIp('203.0.113.3');

        $content = $this->readHtaccess();
        self::assertSame(1, substr_count($content, '# BEGIN Phirewall'));
        self::assertSame(1, substr_count($content, '# END Phirewall'));
    }

    public function testManagedSectionStructure(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');

        $content = $this->readHtaccess();
        $beginPos = strpos($content, '# BEGIN Phirewall');
        $endPos = strpos($content, '# END Phirewall');
        self::assertNotFalse($beginPos);
        self::assertNotFalse($endPos);

        // Extract managed section
        $managed = substr($content, $beginPos, ($endPos + strlen('# END Phirewall')) - $beginPos);
        $lines = explode("\n", $managed);

        // First line is begin marker
        self::assertSame('# BEGIN Phirewall', $lines[0]);
        // Directives in the middle
        self::assertSame('Require not ip 203.0.113.1', $lines[1]);
        self::assertSame('Require not ip 203.0.113.2', $lines[2]);
        // Last line is end marker
        self::assertSame('# END Phirewall', $lines[3]);
    }

    // ─── Edge cases: empty IP, invalid IP format ─────────────────────

    public function testBlockEmptyIpThrowsInvalidArgument(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must not be empty');
        $adapter->blockIp('');
    }

    public function testBlockWhitespaceOnlyIpThrowsInvalidArgument(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must not be empty');
        $adapter->blockIp('   ');
    }

    public function testUnblockEmptyIpThrowsInvalidArgument(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $adapter->unblockIp('');
    }

    public function testIsBlockedEmptyIpThrowsInvalidArgument(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $adapter->isBlocked('');
    }

    #[DataProvider('invalidIpProvider')]
    public function testBlockInvalidIpFormatsThrow(string $invalidIp): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $adapter->blockIp($invalidIp);
    }

    #[DataProvider('invalidIpProvider')]
    public function testUnblockInvalidIpFormatsThrow(string $invalidIp): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $adapter->unblockIp($invalidIp);
    }

    #[DataProvider('invalidIpProvider')]
    public function testIsBlockedInvalidIpFormatsThrow(string $invalidIp): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(InvalidArgumentException::class);
        $adapter->isBlocked($invalidIp);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidIpProvider(): iterable
    {
        yield 'random string' => ['not_an_ip'];
        yield 'hostname' => ['example.com'];
        yield 'partial ipv4' => ['192.168.1'];
        yield 'ipv4 overflow' => ['256.1.1.1'];
        yield 'ipv4 with port' => ['192.168.1.1:8080'];
        yield 'cidr notation' => ['10.0.0.0/8'];
        yield 'negative number' => ['-1.0.0.0'];
        yield 'html injection attempt' => ['<script>alert(1)</script>'];
        yield 'newline injection' => ["192.168.1.1\nRequire all denied"];
    }

    // ─── isBlocked ───────────────────────────────────────────────────

    public function testIsBlockedReflectsCurrentState(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        self::assertFalse($adapter->isBlocked('203.0.113.11'));
        $adapter->blockIp('203.0.113.11');
        self::assertTrue($adapter->isBlocked('203.0.113.11'));
        $adapter->unblockIp('203.0.113.11');
        self::assertFalse($adapter->isBlocked('203.0.113.11'));
    }

    public function testIsBlockedDistinguishesDifferentIps(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        self::assertTrue($adapter->isBlocked('203.0.113.1'));
        self::assertFalse($adapter->isBlocked('203.0.113.2'));
    }

    // ─── File I/O edge cases ─────────────────────────────────────────

    public function testBlockThrowsWhenDirectoryDoesNotExist(): void
    {
        $adapter = new ApacheHtaccessAdapter('/tmp/non_existent_dir_' . bin2hex(random_bytes(8)) . '/.htaccess');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Directory does not exist');
        $adapter->blockIp('203.0.113.1');
    }

    public function testEmptyHtaccessFileCreatesProperManagedSection(): void
    {
        file_put_contents($this->htaccess, '');

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringContainsString('# END Phirewall', $content);
    }

    public function testHtaccessWithOnlyWhitespaceCreatesProperSection(): void
    {
        file_put_contents($this->htaccess, "  \n\n  \n");

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
    }

    public function testCorruptedMarkersBeginWithoutEndTreatsAsNoSection(): void
    {
        file_put_contents($this->htaccess, "# Before\n# BEGIN Phirewall\nRequire not ip 10.0.0.1\n");

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $content = $this->readHtaccess();
        // The old corrupt content becomes "before" content, and a new managed section is created
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        // Should have exactly one proper pair of markers
        self::assertSame(1, substr_count($content, '# END Phirewall'));
    }

    public function testReversedMarkersTreatsAsNoSection(): void
    {
        // END before BEGIN is invalid
        file_put_contents($this->htaccess, "# END Phirewall\n# BEGIN Phirewall\n");

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
    }

    // ─── Atomic file write ───────────────────────────────────────────

    public function testBlockDoesNotLeaveTemporaryFiles(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        // glob('*') does not match dotfiles; check for .htaccess.tmp.* leftovers explicitly
        $tmpFiles = glob($this->tmpDir . '/.htaccess.tmp.*') ?: [];

        self::assertSame([], $tmpFiles, 'No temporary files should remain after atomic write');
        self::assertFileExists($this->htaccess);
    }

    public function testBlockPreservesExistingFilePermissions(): void
    {
        file_put_contents($this->htaccess, "# test\n");
        chmod($this->htaccess, 0644);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        $perms = fileperms($this->htaccess) & 0777;
        self::assertSame(0644, $perms, 'File permissions should be preserved after atomic write');
    }

    // ─── Valid IP formats that should be accepted ────────────────────

    #[DataProvider('validIpProvider')]
    public function testBlockAcceptsValidIpFormats(string $ip): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp($ip);

        self::assertTrue($adapter->isBlocked($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validIpProvider(): iterable
    {
        yield 'ipv4 standard' => ['192.168.1.1'];
        yield 'ipv4 loopback' => ['127.0.0.1'];
        yield 'ipv4 zeroes' => ['0.0.0.0'];
        yield 'ipv4 broadcast' => ['255.255.255.255'];
        yield 'ipv4 private class A' => ['10.0.0.1'];
        yield 'ipv6 loopback' => ['::1'];
        yield 'ipv6 full' => ['2001:db8:85a3:0:0:8a2e:370:7334'];
        yield 'ipv6 compressed' => ['2001:db8::1'];
        yield 'ipv6 all zeros' => ['::'];
    }

    // ─── IP trimming ─────────────────────────────────────────────────

    public function testIpAddressWithLeadingTrailingWhitespaceIsTrimmed(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('  203.0.113.1  ');

        self::assertTrue($adapter->isBlocked('203.0.113.1'));
        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringNotContainsString('Require not ip   203.0.113.1', $content);
    }

    // ─── Full lifecycle ──────────────────────────────────────────────

    public function testFullBlockUnblockLifecycle(): void
    {
        $preamble = "Options -Indexes\nRewriteEngine On\n";
        file_put_contents($this->htaccess, $preamble);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        // Block several IPs
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');
        $adapter->blockIp('2001:db8::1');

        self::assertTrue($adapter->isBlocked('203.0.113.1'));
        self::assertTrue($adapter->isBlocked('203.0.113.2'));
        self::assertTrue($adapter->isBlocked('2001:db8::1'));

        // Unblock one
        $adapter->unblockIp('203.0.113.2');
        self::assertTrue($adapter->isBlocked('203.0.113.1'));
        self::assertFalse($adapter->isBlocked('203.0.113.2'));
        self::assertTrue($adapter->isBlocked('2001:db8::1'));

        // Block another
        $adapter->blockIp('198.51.100.1');
        self::assertTrue($adapter->isBlocked('198.51.100.1'));

        // Unblock all
        $adapter->unblockMany(['203.0.113.1', '2001:db8::1', '198.51.100.1']);
        self::assertFalse($adapter->isBlocked('203.0.113.1'));
        self::assertFalse($adapter->isBlocked('2001:db8::1'));
        self::assertFalse($adapter->isBlocked('198.51.100.1'));

        // Preamble should still be there
        $content = $this->readHtaccess();
        self::assertStringContainsString('Options -Indexes', $content);
        self::assertStringContainsString('RewriteEngine On', $content);
    }

    // ─── Separate adapter instances sharing the same file ────────────

    public function testSeparateInstancesShareState(): void
    {
        $adapter1 = new ApacheHtaccessAdapter($this->htaccess);
        $adapter2 = new ApacheHtaccessAdapter($this->htaccess);

        $adapter1->blockIp('203.0.113.1');
        self::assertTrue($adapter2->isBlocked('203.0.113.1'));

        $adapter2->unblockIp('203.0.113.1');
        self::assertFalse($adapter1->isBlocked('203.0.113.1'));
    }

    // ─── Integration with InfrastructureBanListener ──────────────────

    public function testIntegrationWithInfrastructureBanListenerViaFail2Ban(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $runner = new \Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner();
        $listener = new \Flowd\Phirewall\Infrastructure\InfrastructureBanListener(
            $adapter,
            $runner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
        );

        $event = new \Flowd\Phirewall\Events\Fail2BanBanned(
            rule: 'login',
            key: '203.0.113.50',
            threshold: 5,
            period: 300,
            banSeconds: 3600,
            count: 5,
            serverRequest: new \Nyholm\Psr7\ServerRequest('GET', '/'),
        );

        $listener->onFail2BanBanned($event);

        self::assertTrue($adapter->isBlocked('203.0.113.50'));
        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 203.0.113.50', $content);
    }

    public function testIntegrationWithInfrastructureBanListenerViaBlocklist(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $runner = new \Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner();
        $listener = new \Flowd\Phirewall\Infrastructure\InfrastructureBanListener(
            $adapter,
            $runner,
            blockOnFail2Ban: false,
            blockOnBlocklist: true,
        );

        $request = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $event = new \Flowd\Phirewall\Events\BlocklistMatched('rule-x', $request);

        $listener->onBlocklistMatched($event);

        self::assertTrue($adapter->isBlocked('198.51.100.77'));
    }

    public function testIntegrationListenerDoesNotBlockWhenFail2BanDisabled(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $runner = new \Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner();
        $listener = new \Flowd\Phirewall\Infrastructure\InfrastructureBanListener(
            $adapter,
            $runner,
            blockOnFail2Ban: false,
            blockOnBlocklist: false,
        );

        $event = new \Flowd\Phirewall\Events\Fail2BanBanned(
            rule: 'login',
            key: '203.0.113.50',
            threshold: 5,
            period: 300,
            banSeconds: 3600,
            count: 5,
            serverRequest: new \Nyholm\Psr7\ServerRequest('GET', '/'),
        );

        $listener->onFail2BanBanned($event);

        self::assertFalse($adapter->isBlocked('203.0.113.50'));
    }

    public function testIntegrationListenerWithCustomKeyToIpMapper(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $runner = new \Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner();
        $listener = new \Flowd\Phirewall\Infrastructure\InfrastructureBanListener(
            $adapter,
            $runner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
            keyToIp: static fn(string $key): ?string => $key === 'user:42' ? '203.0.113.99' : null,
        );

        // Event with a key that maps to an IP
        $event = new \Flowd\Phirewall\Events\Fail2BanBanned(
            rule: 'login',
            key: 'user:42',
            threshold: 5,
            period: 300,
            banSeconds: 3600,
            count: 5,
            serverRequest: new \Nyholm\Psr7\ServerRequest('GET', '/'),
        );

        $listener->onFail2BanBanned($event);
        self::assertTrue($adapter->isBlocked('203.0.113.99'));

        // Event with a key that returns null (should be skipped)
        $event2 = new \Flowd\Phirewall\Events\Fail2BanBanned(
            rule: 'login',
            key: 'user:99',
            threshold: 5,
            period: 300,
            banSeconds: 3600,
            count: 5,
            serverRequest: new \Nyholm\Psr7\ServerRequest('GET', '/'),
        );

        $listener->onFail2BanBanned($event2);
        // Only the first IP should be blocked
        self::assertTrue($adapter->isBlocked('203.0.113.99'));
        $content = $this->readHtaccess();
        self::assertSame(1, substr_count($content, 'Require not ip'));
    }

    // ─── Unblock all IPs ────────────────────────────────────────

    public function testUnblockingAllIpsLeavesEmptyManagedSection(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        $adapter->blockIp('203.0.113.2');

        $adapter->unblockMany(['203.0.113.1', '203.0.113.2']);

        $content = $this->readHtaccess();
        self::assertStringContainsString('# BEGIN Phirewall', $content);
        self::assertStringContainsString('# END Phirewall', $content);
        self::assertStringNotContainsString('Require not ip', $content);
    }

    // ─── New file permissions ───────────────────────────────────

    public function testNewHtaccessFileIsReadable(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');

        self::assertFileIsReadable($this->htaccess);
    }

    // ─── Large number of IPs ────────────────────────────────────

    public function testBlockManyWithLargeNumberOfIps(): void
    {
        $ips = [];
        for ($index = 1; $index <= 100; $index++) {
            $ips[] = '10.0.0.' . $index;
        }

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany($ips);

        $content = $this->readHtaccess();
        self::assertSame(100, substr_count($content, 'Require not ip'));
        self::assertTrue($adapter->isBlocked('10.0.0.1'));
        self::assertTrue($adapter->isBlocked('10.0.0.100'));
        self::assertFalse($adapter->isBlocked('10.0.0.101'));
    }

    // ─── Mixed block and unblock many ───────────────────────────

    public function testBlockManyThenUnblockManyPreservesRemainingOrder(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany(['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4']);

        $adapter->unblockMany(['203.0.113.2', '203.0.113.4']);

        $content = $this->readHtaccess();
        self::assertStringContainsString('Require not ip 203.0.113.1', $content);
        self::assertStringNotContainsString('Require not ip 203.0.113.2', $content);
        self::assertStringContainsString('Require not ip 203.0.113.3', $content);
        self::assertStringNotContainsString('Require not ip 203.0.113.4', $content);

        // Verify remaining order is preserved
        $pos1 = strpos($content, 'Require not ip 203.0.113.1');
        $pos3 = strpos($content, 'Require not ip 203.0.113.3');
        self::assertNotFalse($pos1);
        self::assertNotFalse($pos3);
        self::assertLessThan($pos3, $pos1);
    }

    // ─── isBlocked on file that was externally modified ─────────

    public function testIsBlockedReadsFromDiskEachTime(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.1');
        self::assertTrue($adapter->isBlocked('203.0.113.1'));

        // Externally remove the managed section
        file_put_contents($this->htaccess, "# Empty file\n");

        self::assertFalse(
            $adapter->isBlocked('203.0.113.1'),
            'isBlocked should re-read the file and detect external changes'
        );
    }

    // ─── unblockMany validates all IPs before modifying file ────

    public function testUnblockManyValidatesAllIpsBeforeModifying(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockMany(['203.0.113.1', '203.0.113.2']);
        $contentBefore = $this->readHtaccess();

        try {
            $adapter->unblockMany(['203.0.113.1', 'invalid_ip']);
            self::fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException) {
            // expected
        }

        // File should not have been modified because validation failed before write
        $contentAfter = $this->readHtaccess();
        self::assertSame(
            $contentBefore,
            $contentAfter,
            'File should not change when unblockMany validation fails'
        );
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    private function readHtaccess(): string
    {
        return (string) file_get_contents($this->htaccess);
    }
}
