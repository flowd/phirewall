<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Infrastructure;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class InfrastructureBanListenerTest extends TestCase
{
    public function testFail2BanBannedSchedulesBlock(): void
    {
        $recordingBlocker = new \Flowd\Phirewall\Tests\Support\RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener($recordingBlocker, $syncNonBlockingRunner, blockOnFail2Ban: true, blockOnBlocklist: false);

        $fail2BanBanned = new Fail2BanBanned('login', '203.0.113.50', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $infrastructureBanListener->onFail2BanBanned($fail2BanBanned);

        $this->assertSame([
            ['op' => 'block', 'ip' => '203.0.113.50']
        ], $recordingBlocker->calls);
    }

    public function testBlocklistMatchedUsesRequestIpWhenEnabled(): void
    {
        $recordingBlocker = new \Flowd\Phirewall\Tests\Support\RecordingBlocker();
        $syncNonBlockingRunner = new SyncNonBlockingRunner();
        $infrastructureBanListener = new InfrastructureBanListener($recordingBlocker, $syncNonBlockingRunner, blockOnFail2Ban: false, blockOnBlocklist: true);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $blocklistMatched = new BlocklistMatched('rule-x', $serverRequest);
        $infrastructureBanListener->onBlocklistMatched($blocklistMatched);

        $this->assertSame([
            ['op' => 'block', 'ip' => '198.51.100.77']
        ], $recordingBlocker->calls);
    }
}
