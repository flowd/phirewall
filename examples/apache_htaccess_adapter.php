<?php

declare(strict_types=1);

/**
 * Example: Apache .htaccess Adapter for IP Blocking
 *
 * This example demonstrates how to use the ApacheHtaccessAdapter to block and
 * unblock IP addresses at the web server level by maintaining a managed section
 * inside an .htaccess file.
 *
 * Requirements and notes:
 * - Apache 2.4+ with mod_authz_core (for "Require" directives)
 * - The adapter is optional and does not affect normal middleware behavior
 * - Writes are atomic (temp file + rename) and preserve unrelated .htaccess content
 * - All operations are idempotent
 * - For safety, this example uses a temporary .htaccess file in your system temp directory
 */

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;

// Create a temp directory and .htaccess path for demonstration
$demoDir = sys_get_temp_dir() . '/phirewall_htaccess_example_' . bin2hex(random_bytes(4));
if (!is_dir($demoDir) && !mkdir($demoDir, 0777, true) && !is_dir($demoDir)) {
    throw new \RuntimeException(sprintf('Directory "%s" was not created', $demoDir));
}

$htaccessPath = $demoDir . '/.htaccess';

// Optional pre-existing content in .htaccess to show preservation behavior
file_put_contents($htaccessPath, "# Demo app settings\nOptions -Indexes\n\n# Some unrelated section\n");

$adapter = new ApacheHtaccessAdapter($htaccessPath);

// Basic single-IP operations
$adapter->blockIp('203.0.113.10');
$adapter->blockIp('2001:db8::1'); // IPv6 supported

// Idempotent duplicate
$adapter->blockIp('203.0.113.10');

echo "After blocking two IPs, managed section contains:\n";
$contents = (string) file_get_contents($htaccessPath);
echo $contents . "\n";

echo "isBlocked(203.0.113.10): ";
var_export($adapter->isBlocked('203.0.113.10')); echo "\n";

echo "isBlocked(198.51.100.99): ";
var_export($adapter->isBlocked('198.51.100.99')); echo "\n\n";

// Batch operations
$adapter->blockMany(['198.51.100.20', '198.51.100.21', '2001:db8::5']);
$adapter->unblockMany(['203.0.113.10']);

echo "After batch block/unblock, managed section contains:\n";
$contents = (string) file_get_contents($htaccessPath);
echo $contents . "\n";

// Example: wiring the optional InfrastructureBanListener (non-blocking)
// Normally you would register this listener with your application's PSR-14 dispatcher.
$runner = new SyncNonBlockingRunner();
$listener = new InfrastructureBanListener(
    $adapter,
    $runner,
    true,  // blockOnFail2Ban: mirror Fail2Ban bans to Apache
    true   // blockOnBlocklist: mirror Blocklist matches to Apache
);

// Minimal demo dispatcher that calls our listener methods for relevant events
$dispatcher = new class ($listener) implements EventDispatcherInterface {
    public function __construct(private readonly InfrastructureBanListener $infrastructureBanListener) {}

    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            $this->infrastructureBanListener->onFail2BanBanned($event);
        }

        if ($event instanceof BlocklistMatched) {
            $this->infrastructureBanListener->onBlocklistMatched($event);
        }

        return $event;
    }
};

// Simulate a Fail2Ban ban event (key is the offending IP by default)
$dispatcher->dispatch(new Fail2BanBanned(
    rule: 'login',
    key: '198.51.100.77',
    threshold: 5,
    period: 300,
    banSeconds: 3600,
    count: 5,
    serverRequest: new ServerRequest('GET', '/')
));

// Simulate a Blocklist match; listener maps request->REMOTE_ADDR to IP
$dispatcher->dispatch(new BlocklistMatched(
    rule: 'block-admin',
    serverRequest: new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.250'])
));

echo "After listener-driven blocks, managed section contains:\n";
$contents = (string) file_get_contents($htaccessPath);
echo $contents . "\n";

echo sprintf('Demo .htaccess path: %s%s', $htaccessPath, PHP_EOL);
echo "You can inspect this file to see the managed section between markers.\n";
