<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use PHPUnit\Framework\TestCase;

final class ApacheHtaccessAdapterBatchTest extends TestCase
{
    private string $tmpDir = '';
    private string $htaccess = '';

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/phirewall_test_' . bin2hex(random_bytes(4));
        mkdir($this->tmpDir);
        $this->htaccess = $this->tmpDir . '/.htaccess';
    }

    protected function tearDown(): void
    {
        if (is_file($this->htaccess)) {
            @unlink($this->htaccess);
        }
        if (is_dir($this->tmpDir)) {
            @rmdir($this->tmpDir);
        }
    }

    public function testBlockManyAndUnblockManyAreAtomicAndIdempotent(): void
    {
        file_put_contents($this->htaccess, "# Some prelude\nAllowOverride All\n\n");
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        // Block multiple, including duplicates and mixed IPv4/IPv6
        $adapter->blockMany(['203.0.113.10', '2001:db8::1', '203.0.113.10']);

        $content = (string)file_get_contents($this->htaccess);
        $this->assertStringContainsString('# BEGIN Phirewall', $content);
        $this->assertStringContainsString('Require not ip 203.0.113.10', $content);
        $this->assertStringContainsString('Require not ip 2001:db8::1', $content);

        // Idempotent second call should not duplicate lines
        $adapter->blockMany(['2001:db8::1']);
        $content2 = (string)file_get_contents($this->htaccess);
        $this->assertSame($content, $content2, 'Second identical blockMany should not change file');

        // Remove subset and ensure others remain
        $adapter->unblockMany(['203.0.113.10']);
        $content3 = (string)file_get_contents($this->htaccess);
        $this->assertStringNotContainsString('Require not ip 203.0.113.10', $content3);
        $this->assertStringContainsString('Require not ip 2001:db8::1', $content3);

        // Removing non-existent IPs is a no-op
        $adapter->unblockMany(['203.0.113.10']);
        $content4 = (string)file_get_contents($this->htaccess);
        $this->assertSame($content3, $content4);
    }

    public function testBlockManyWithInvalidIpThrowsAndDoesNotModifyFile(): void
    {
        file_put_contents($this->htaccess, "# Prelude\n");
        $adapter = new ApacheHtaccessAdapter($this->htaccess);

        $this->expectException(\InvalidArgumentException::class);
        try {
            $adapter->blockMany(['203.0.113.10', 'not_an_ip']);
        } finally {
            $content = (string)file_get_contents($this->htaccess);
            // No managed section should have been created
            $this->assertStringNotContainsString('# BEGIN Phirewall', $content);
            $this->assertStringNotContainsString('Require not ip 203.0.113.10', $content);
        }
    }
}
