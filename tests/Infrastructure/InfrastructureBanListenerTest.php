<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\InfrastructureBlockerInterface;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Tests\Support\RecordingBlocker;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class InfrastructureBanListenerTest extends TestCase
{
    public function testFail2BanBannedSchedulesBlock(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
        );

        $fail2BanBanned = new Fail2BanBanned('login', '203.0.113.50', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);

        $this->assertSame([
            ['op' => 'block', 'ip' => '203.0.113.50'],
        ], $recordingBlocker->calls);
    }

    public function testFail2BanBannedDoesNothingWhenDisabled(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: false,
        );

        $fail2BanBanned = new Fail2BanBanned('login', '203.0.113.50', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);

        $this->assertSame([], $recordingBlocker->calls, 'No calls should be made when Fail2Ban blocking is disabled');
    }

    public function testFail2BanBannedSkipsWhenKeyToIpReturnsNull(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
            keyToIp: static fn(string $key): ?string => null,
        );

        $fail2BanBanned = new Fail2BanBanned('login', 'user:99', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);

        $this->assertSame([], $recordingBlocker->calls, 'No calls should be made when keyToIp returns null');
    }

    public function testFail2BanBannedSkipsWhenKeyToIpReturnsEmptyString(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
            keyToIp: static fn(string $key): string => '',
        );

        $fail2BanBanned = new Fail2BanBanned('login', 'user:42', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);

        $this->assertSame([], $recordingBlocker->calls, 'No calls should be made when keyToIp returns empty string');
    }

    public function testFail2BanBannedSwallowsBlockerExceptions(): void
    {
        $throwingBlocker = new class () implements InfrastructureBlockerInterface {
            public function blockIp(string $ipAddress): void
            {
                throw new \RuntimeException('Disk full');
            }

            public function unblockIp(string $ipAddress): void
            {
            }

            public function isBlocked(string $ipAddress): bool
            {
                return false;
            }
        };

        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $throwingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: true,
            blockOnBlocklist: false,
        );

        $fail2BanBanned = new Fail2BanBanned('login', '203.0.113.50', 5, 300, 3600, 5, new ServerRequest('GET', '/'));

        // Should not throw -- exception is swallowed by the runner and listener
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);
        $this->addToAssertionCount(1);
    }

    public function testBlocklistMatchedUsesRequestIpWhenEnabled(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: true,
        );

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);

        $this->assertSame([
            ['op' => 'block', 'ip' => '198.51.100.77'],
        ], $recordingBlocker->calls);
    }

    public function testBlocklistMatchedDoesNothingWhenDisabled(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: false,
        );

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);

        $this->assertSame([], $recordingBlocker->calls, 'No calls should be made when blocklist blocking is disabled');
    }

    public function testBlocklistMatchedSkipsWhenRequestHasNoIp(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: true,
        );

        // ServerRequest without REMOTE_ADDR
        $serverRequest = new ServerRequest('GET', '/');
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);

        $this->assertSame([], $recordingBlocker->calls, 'No calls should be made when request has no IP');
    }

    public function testBlocklistMatchedSwallowsBlockerExceptions(): void
    {
        $throwingBlocker = new class () implements InfrastructureBlockerInterface {
            public function blockIp(string $ipAddress): void
            {
                throw new \RuntimeException('Permission denied');
            }

            public function unblockIp(string $ipAddress): void
            {
            }

            public function isBlocked(string $ipAddress): bool
            {
                return false;
            }
        };

        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $throwingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: true,
        );

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);

        // Should not throw -- exception is swallowed
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);
        $this->addToAssertionCount(1);
    }

    public function testCustomRequestToIpExtractor(): void
    {
        $recordingBlocker = new RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener(
            $recordingBlocker,
            $syncNonBlockingRunner,
            blockOnFail2Ban: false,
            blockOnBlocklist: true,
            requestToIp: static fn(\Psr\Http\Message\ServerRequestInterface $serverRequest): ?string => in_array($serverRequest->getHeaderLine('X-Real-IP'), ['', '0'], true) ? null : $serverRequest->getHeaderLine('X-Real-IP'),
        );

        $serverRequest = (new ServerRequest('GET', '/'))->withHeader('X-Real-IP', '10.0.0.42');
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);

        $this->assertSame([
            ['op' => 'block', 'ip' => '10.0.0.42'],
        ], $recordingBlocker->calls);
    }
}
