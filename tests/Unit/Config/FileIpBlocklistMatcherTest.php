<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\FileIpBlocklistMatcher;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

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

    public function testIpv4MappedIpv6PeerMatchesIpv4EntryAndCidr(): void
    {
        $root = vfsStream::setup('blocklist');
        vfsStream::newFile('blocklist.txt')->at($root)->setContent("1.2.3.4\n10.0.0.0/24\n");
        $file = $root->getChild('blocklist.txt')->url();

        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($file, null, 0);

        // A dual-stack host presents an IPv4 client as ::ffff:x.x.x.x; it must
        // still match IPv4 entries written in plain notation.
        $exactRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:1.2.3.4']);
        $this->assertTrue($fileIpBlocklistMatcher->match($exactRequest)->isMatch(), 'Mapped peer should match IPv4 exact entry');

        $cidrRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:10.0.0.50']);
        $this->assertTrue($fileIpBlocklistMatcher->match($cidrRequest)->isMatch(), 'Mapped peer should match IPv4 CIDR entry');

        $miss = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '::ffff:8.8.8.8']);
        $this->assertFalse($fileIpBlocklistMatcher->match($miss)->isMatch());
    }

    public function testMatchWithResolverUsesSuppliedDefaultWhenNoExplicitResolver(): void
    {
        $root = vfsStream::setup('blocklist');
        vfsStream::newFile('blocklist.txt')->at($root)->setContent("203.0.113.7\n");
        $file = $root->getChild('blocklist.txt')->url();

        // No explicit resolver: the supplied default reads the client IP from X-Real-IP.
        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($file, null, 0);
        $serverRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Real-IP', '203.0.113.7');

        $matchResult = $fileIpBlocklistMatcher->matchWithResolver($serverRequest, $this->headerResolver('X-Real-IP'));
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('203.0.113.7', $matchResult->metadata()['ip']);
    }

    public function testMatchWithResolverExplicitResolverWinsOverDefault(): void
    {
        $root = vfsStream::setup('blocklist');
        vfsStream::newFile('blocklist.txt')->at($root)->setContent("203.0.113.7\n");
        $file = $root->getChild('blocklist.txt')->url();

        // Explicit resolver (X-Trusted-IP) is used, not the supplied default (X-Real-IP).
        $fileIpBlocklistMatcher = new FileIpBlocklistMatcher($file, $this->headerResolver('X-Trusted-IP'), 0);
        $serverRequest = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withHeader('X-Trusted-IP', '203.0.113.7')
            ->withHeader('X-Real-IP', '198.51.100.9');

        $this->assertTrue($fileIpBlocklistMatcher->matchWithResolver($serverRequest, $this->headerResolver('X-Real-IP'))->isMatch());
    }

    /**
     * A resolver that reads the client IP from the named header (null when absent).
     *
     * @return callable(ServerRequestInterface): ?string
     */
    private function headerResolver(string $header): callable
    {
        return static function (ServerRequestInterface $serverRequest) use ($header): ?string {
            $value = $serverRequest->getHeaderLine($header);
            return $value === '' ? null : $value;
        };
    }
}
