<?php

/**
 * Example 12: Apache .htaccess Adapter
 *
 * This example demonstrates how to use the ApacheHtaccessAdapter to block
 * IP addresses at the web server level by maintaining a managed section
 * inside an .htaccess file.
 *
 * Features shown:
 * - Blocking IPs at Apache level (before PHP)
 * - Automatic .htaccess management
 * - Integration with Fail2Ban events
 * - IPv4 and IPv6 support
 * - Atomic file updates (safe for concurrent writes)
 *
 * Requirements:
 * - Apache 2.4+ with mod_authz_core
 * - Writable .htaccess file location
 *
 * Run: php examples/12-apache-htaccess.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;

echo "=== Apache .htaccess Adapter Example ===\n\n";

// =============================================================================
// SETUP
// =============================================================================

// Create a temporary directory and .htaccess path for demonstration
$demoDir = sys_get_temp_dir() . '/phirewall_htaccess_example_' . bin2hex(random_bytes(4));
if (!is_dir($demoDir) && !mkdir($demoDir, 0777, true) && !is_dir($demoDir)) {
    throw new RuntimeException(sprintf('Directory "%s" was not created', $demoDir));
}

$htaccessPath = $demoDir . '/.htaccess';
echo "Demo .htaccess path: $htaccessPath\n\n";

// Create an .htaccess with some pre-existing content
file_put_contents($htaccessPath, <<<'HTACCESS'
# Demo application settings
Options -Indexes
ErrorDocument 404 /404.html

# Some unrelated rewrite rules
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^ index.php [L]

HTACCESS
);

echo "Created .htaccess with existing content\n\n";

// =============================================================================
// ADAPTER SETUP
// =============================================================================

$adapter = new ApacheHtaccessAdapter($htaccessPath);
echo "ApacheHtaccessAdapter initialized\n\n";

// =============================================================================
// BASIC OPERATIONS
// =============================================================================

echo "=== Basic IP Blocking ===\n\n";

// Block individual IPs
$adapter->blockIp('203.0.113.10');
echo "Blocked: 203.0.113.10\n";

$adapter->blockIp('203.0.113.11');
echo "Blocked: 203.0.113.11\n";

$adapter->blockIp('2001:db8::1');
echo "Blocked: 2001:db8::1 (IPv6)\n";

// Idempotent - blocking same IP again is safe
$adapter->blockIp('203.0.113.10');
echo "Blocked: 203.0.113.10 (duplicate - ignored)\n\n";

// Check if IPs are blocked
echo "IP Status:\n";
echo sprintf("  203.0.113.10: %s\n", $adapter->isBlocked('203.0.113.10') ? 'BLOCKED' : 'allowed');
echo sprintf("  203.0.113.99: %s\n", $adapter->isBlocked('203.0.113.99') ? 'BLOCKED' : 'allowed');
echo sprintf("  2001:db8::1:  %s\n", $adapter->isBlocked('2001:db8::1') ? 'BLOCKED' : 'allowed');
echo "\n";

// =============================================================================
// BATCH OPERATIONS
// =============================================================================

echo "=== Batch Operations ===\n\n";

// Block multiple IPs at once
$adapter->blockMany([
    '198.51.100.20',
    '198.51.100.21',
    '198.51.100.22',
    '2001:db8::5',
]);
echo "Batch blocked: 198.51.100.20-22, 2001:db8::5\n";

// Unblock specific IPs
$adapter->unblockMany(['203.0.113.10', '198.51.100.21']);
echo "Batch unblocked: 203.0.113.10, 198.51.100.21\n\n";

// =============================================================================
// SHOW .HTACCESS CONTENTS
// =============================================================================

echo "=== Current .htaccess Contents ===\n\n";
echo file_get_contents($htaccessPath);
echo "\n";

// =============================================================================
// EVENT INTEGRATION
// =============================================================================

echo "=== Event Integration ===\n\n";

// Set up the infrastructure listener
$runner = new SyncNonBlockingRunner();
$listener = new InfrastructureBanListener(
    infrastructureBlocker: $adapter,
    nonBlockingRunner: $runner,
    blockOnFail2Ban: true,      // Mirror Fail2Ban bans to Apache
    blockOnBlocklist: true       // Mirror Blocklist matches to Apache
);

// Create a minimal event dispatcher
$dispatcher = new class ($listener) implements EventDispatcherInterface {
    public function __construct(private readonly InfrastructureBanListener $listener) {}

    public function dispatch(object $event): object
    {
        if ($event instanceof Fail2BanBanned) {
            $this->listener->onFail2BanBanned($event);
        }
        if ($event instanceof BlocklistMatched) {
            $this->listener->onBlocklistMatched($event);
        }
        return $event;
    }
};

echo "InfrastructureBanListener configured\n\n";

// Simulate a Fail2Ban ban event
echo "Simulating Fail2Ban ban event...\n";
$dispatcher->dispatch(new Fail2BanBanned(
    rule: 'login-brute',
    key: '198.51.100.77',
    threshold: 5,
    period: 300,
    banSeconds: 3600,
    count: 5,
    serverRequest: new ServerRequest('POST', '/login')
));
echo "  Fail2Ban banned: 198.51.100.77\n";

// Simulate a Blocklist match event
echo "Simulating Blocklist match event...\n";
$dispatcher->dispatch(new BlocklistMatched(
    rule: 'scanner-block',
    serverRequest: new ServerRequest('GET', '/wp-admin', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.250'])
));
echo "  Blocklist blocked: 203.0.113.250\n\n";

// =============================================================================
// FINAL .HTACCESS
// =============================================================================

echo "=== Final .htaccess Contents ===\n\n";
echo file_get_contents($htaccessPath);
echo "\n";

// =============================================================================
// CLEANUP
// =============================================================================

echo "=== Cleanup ===\n\n";

// Remove temp files
unlink($htaccessPath);
rmdir($demoDir);
echo "Temporary files removed\n\n";

// =============================================================================
// PRODUCTION TIPS
// =============================================================================

echo "=== Production Tips ===\n\n";

echo "1. File Permissions:\n";
echo "   - Ensure .htaccess is writable by PHP process\n";
echo "   - Use appropriate file permissions (644 recommended)\n\n";

echo "2. Apache Configuration:\n";
echo "   - Ensure AllowOverride includes Limit and AuthConfig\n";
echo "   - Test with: httpd -t -D DUMP_MODULES | grep authz\n\n";

echo "3. Performance:\n";
echo "   - Apache-level blocking is faster than PHP-level\n";
echo "   - Consider using mod_evasive for DDoS protection\n\n";

echo "4. Maintenance:\n";
echo "   - The adapter only manages the marked section\n";
echo "   - Other .htaccess content is preserved\n";
echo "   - Use listBlockedIps() to audit blocked IPs\n\n";

echo "5. Integration:\n";
echo "   - Register InfrastructureBanListener with your PSR-14 dispatcher\n";
echo "   - Use with Fail2Ban for automatic IP banning\n";
echo "   - Consider scheduled cleanup of old entries\n";

echo "\n=== Example Complete ===\n";
