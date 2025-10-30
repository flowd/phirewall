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
        $adapter = new \Flowd\Phirewall\Tests\Support\RecordingBlocker();
        $runner = new SyncNonBlockingRunner();
        $listener = new InfrastructureBanListener($adapter, $runner, blockOnFail2Ban: true, blockOnBlocklist: false);

        $event = new Fail2BanBanned('login', '203.0.113.50', 5, 300, 3600, 5, new ServerRequest('GET', '/'));
        $listener->onFail2BanBanned($event);

        $this->assertSame([
            ['op' => 'block', 'ip' => '203.0.113.50']
        ], $adapter->calls);
    }

    public function testBlocklistMatchedUsesRequestIpWhenEnabled(): void
    {
        $adapter = new \Flowd\Phirewall\Tests\Support\RecordingBlocker();
        $runner = new SyncNonBlockingRunner();
        $listener = new InfrastructureBanListener($adapter, $runner, blockOnFail2Ban: false, blockOnBlocklist: true);

        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.77']);
        $event = new BlocklistMatched('rule-x', $request);
        $listener->onBlocklistMatched($event);

        $this->assertSame([
            ['op' => 'block', 'ip' => '198.51.100.77']
        ], $adapter->calls);
    }
}
