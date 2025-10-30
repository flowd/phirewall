<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use PHPUnit\Framework\TestCase;

final class ApacheHtaccessAdapterTest extends TestCase
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

    public function testBlockAndUnblockIpMaintainsMarkersAndIdempotency(): void
    {
        // Pre-existing content
        $initial = "Options -Indexes\n\n# Other config\n";
        file_put_contents($this->htaccess, $initial);

        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('203.0.113.10');
        $adapter->blockIp('2001:db8::1'); // IPv6
        // Duplicate should be idempotent
        $adapter->blockIp('203.0.113.10');

        $content = (string)file_get_contents($this->htaccess);
        $this->assertStringContainsString('# BEGIN Phirewall', $content);
        $this->assertStringContainsString('# END Phirewall', $content);
        $this->assertStringContainsString('Require not ip 203.0.113.10', $content);
        $this->assertStringContainsString('Require not ip 2001:db8::1', $content);

        // Unblock one
        $adapter->unblockIp('203.0.113.10');
        $content2 = (string)file_get_contents($this->htaccess);
        $this->assertStringNotContainsString('Require not ip 203.0.113.10', $content2);
        $this->assertStringContainsString('Require not ip 2001:db8::1', $content2);

        // Unblock missing should be idempotent (no exception)
        $adapter->unblockIp('203.0.113.10');
        $content3 = (string)file_get_contents($this->htaccess);
        $this->assertStringNotContainsString('Require not ip 203.0.113.10', $content3);
    }

    public function testIsBlockedReflectsState(): void
    {
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $this->assertFalse($adapter->isBlocked('203.0.113.11'));
        $adapter->blockIp('203.0.113.11');
        $this->assertTrue($adapter->isBlocked('203.0.113.11'));
        $adapter->unblockIp('203.0.113.11');
        $this->assertFalse($adapter->isBlocked('203.0.113.11'));
    }

    public function testInvalidIpThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $adapter = new ApacheHtaccessAdapter($this->htaccess);
        $adapter->blockIp('not_an_ip');
    }
}
