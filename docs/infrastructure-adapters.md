# Infrastructure Adapters

Phirewall can mirror application-level blocks to web server infrastructure, providing defense-in-depth by blocking malicious IPs before they reach your PHP application.

## Overview

Infrastructure adapters implement `InfrastructureBlockerInterface`:

```php
interface InfrastructureBlockerInterface
{
    public function blockIp(string $ipAddress): void;
    public function unblockIp(string $ipAddress): void;
    public function isBlocked(string $ipAddress): bool;
}
```

> **Note:** `blockMany()` and `unblockMany()` are convenience methods provided by `ApacheHtaccessAdapter`, not part of the interface contract.

---

## Apache .htaccess Adapter

Maintains a managed section in Apache `.htaccess` files using `Require not ip` directives.

### Requirements

- Apache 2.4+ with mod_authz_core
- Write permissions to .htaccess file
- AllowOverride AuthConfig (or All)

### Basic Usage

```php
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;

$adapter = new ApacheHtaccessAdapter('/var/www/app/.htaccess');

// Block IPs
$adapter->blockIp('192.168.1.100');
$adapter->blockIp('2001:db8::1');  // IPv6 supported

// Unblock IPs
$adapter->unblockIp('192.168.1.100');

// Check status
if ($adapter->isBlocked('192.168.1.100')) {
    echo "IP is blocked\n";
}
```

### Batch Operations

```php
// Block multiple IPs atomically
$adapter->blockMany([
    '192.168.1.100',
    '192.168.1.101',
    '10.0.0.50',
]);

// Unblock multiple IPs
$adapter->unblockMany([
    '192.168.1.100',
    '192.168.1.101',
]);
```

### Generated .htaccess Section

```apache
# Existing content preserved above...

# BEGIN Phirewall
Require not ip 192.168.1.101
Require not ip 10.0.0.50
Require not ip 2001:db8::1
# END Phirewall

# Existing content preserved below...
```

### Automatic Event Integration

Use `InfrastructureBanListener` to automatically mirror firewall bans:

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

$adapter = new ApacheHtaccessAdapter('/var/www/app/.htaccess');
$runner = new SyncNonBlockingRunner();

$listener = new InfrastructureBanListener(
    infrastructureBlocker: $adapter,
    nonBlockingRunner: $runner,
    blockOnFail2Ban: true,    // Mirror Fail2Ban bans
    blockOnBlocklist: true     // Mirror blocklist matches
);

// Wire to your PSR-14 dispatcher
$dispatcher = new class ($listener) implements EventDispatcherInterface {
    public function __construct(private InfrastructureBanListener $listener) {}

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

$config = new Config(new InMemoryCache(), $dispatcher);
```

---

## Safety Features

### Atomic Writes

The adapter uses atomic file operations:

1. Write to temporary file
2. Rename temp file to target (atomic on POSIX)
3. Preserve permissions from original file

### IP Validation

All IPs are validated before writing:

- IPv4 addresses validated with `filter_var()`
- IPv6 addresses normalized to canonical form
- Invalid IPs throw `InvalidArgumentException`

### Content Preservation

Only the managed section between markers is modified:

```apache
# Your custom rules here (preserved)
RewriteEngine On
RewriteRule ^(.*)$ index.php [L]

# BEGIN Phirewall
Require not ip 1.2.3.4
# END Phirewall

# More custom rules (preserved)
Options -Indexes
```

### Idempotent Operations

- Blocking an already-blocked IP is a no-op
- Unblocking a non-blocked IP is a no-op
- Duplicate IPs in batch operations are deduplicated

---

## NonBlockingRunner Interface

Infrastructure operations can be async to avoid blocking request processing:

```php
interface NonBlockingRunnerInterface
{
    public function run(callable $task): void;
}
```

### SyncNonBlockingRunner

Executes tasks synchronously (simplest option):

```php
$runner = new \Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner();
```

### Custom Async Runner

For frameworks with async support:

```php
use Flowd\Phirewall\Infrastructure\NonBlockingRunnerInterface;

// ReactPHP example
$runner = new class ($loop) implements NonBlockingRunnerInterface {
    public function __construct(private LoopInterface $loop) {}

    public function run(callable $task): void
    {
        $this->loop->futureTick($task);
    }
};

// Queue-based example
$runner = new class ($queue) implements NonBlockingRunnerInterface {
    public function __construct(private QueueInterface $queue) {}

    public function run(callable $task): void
    {
        $this->queue->push(new ClosureJob($task));
    }
};
```

---

## Building Custom Adapters

### Nginx Example (Concept)

```php
use Flowd\Phirewall\Infrastructure\InfrastructureBlockerInterface;

class NginxBlocklistAdapter implements InfrastructureBlockerInterface
{
    public function __construct(
        private string $blocklistPath,
        private string $nginxReloadCommand = 'nginx -s reload'
    ) {}

    public function blockIp(string $ipAddress): void
    {
        $this->blockMany([$ipAddress]);
    }

    public function unblockIp(string $ipAddress): void
    {
        $this->unblockMany([$ipAddress]);
    }

    public function isBlocked(string $ipAddress): bool
    {
        $content = file_get_contents($this->blocklistPath) ?: '';
        return str_contains($content, "deny {$ipAddress};");
    }

    public function blockMany(array $ipAddresses): void
    {
        $current = $this->readBlocklist();
        $merged = array_unique(array_merge($current, $ipAddresses));
        $this->writeBlocklist($merged);
        $this->reload();
    }

    public function unblockMany(array $ipAddresses): void
    {
        $current = $this->readBlocklist();
        $filtered = array_diff($current, $ipAddresses);
        $this->writeBlocklist(array_values($filtered));
        $this->reload();
    }

    private function readBlocklist(): array
    {
        if (!file_exists($this->blocklistPath)) {
            return [];
        }
        preg_match_all('/deny\s+([^;]+);/', file_get_contents($this->blocklistPath), $matches);
        return $matches[1] ?? [];
    }

    private function writeBlocklist(array $ips): void
    {
        $content = "# Phirewall blocklist - auto-generated\n";
        foreach ($ips as $ip) {
            $content .= "deny {$ip};\n";
        }
        file_put_contents($this->blocklistPath, $content);
    }

    private function reload(): void
    {
        exec($this->nginxReloadCommand);
    }
}
```

### Firewall/iptables Example (Concept)

```php
class IptablesAdapter implements InfrastructureBlockerInterface
{
    private string $chainName = 'PHIREWALL';

    public function blockIp(string $ipAddress): void
    {
        exec("iptables -A {$this->chainName} -s {$ipAddress} -j DROP");
    }

    public function unblockIp(string $ipAddress): void
    {
        exec("iptables -D {$this->chainName} -s {$ipAddress} -j DROP 2>/dev/null");
    }

    public function isBlocked(string $ipAddress): bool
    {
        $output = shell_exec("iptables -L {$this->chainName} -n");
        return str_contains($output ?? '', $ipAddress);
    }

    public function blockMany(array $ipAddresses): void
    {
        foreach ($ipAddresses as $ip) {
            $this->blockIp($ip);
        }
    }

    public function unblockMany(array $ipAddresses): void
    {
        foreach ($ipAddresses as $ip) {
            $this->unblockIp($ip);
        }
    }
}
```

### Redis Blocklist Example

```php
class RedisBlocklistAdapter implements InfrastructureBlockerInterface
{
    public function __construct(
        private \Predis\Client $redis,
        private string $setKey = 'phirewall:blocked_ips'
    ) {}

    public function blockIp(string $ipAddress): void
    {
        $this->redis->sadd($this->setKey, [$ipAddress]);
    }

    public function unblockIp(string $ipAddress): void
    {
        $this->redis->srem($this->setKey, $ipAddress);
    }

    public function isBlocked(string $ipAddress): bool
    {
        return (bool) $this->redis->sismember($this->setKey, $ipAddress);
    }

    public function blockMany(array $ipAddresses): void
    {
        if ($ipAddresses !== []) {
            $this->redis->sadd($this->setKey, $ipAddresses);
        }
    }

    public function unblockMany(array $ipAddresses): void
    {
        if ($ipAddresses !== []) {
            $this->redis->srem($this->setKey, ...$ipAddresses);
        }
    }
}
```

---

## Complete Integration Example

```php
<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\RedisCache;
use Flowd\Phirewall\Infrastructure\ApacheHtaccessAdapter;
use Flowd\Phirewall\Infrastructure\InfrastructureBanListener;
use Flowd\Phirewall\Infrastructure\SyncNonBlockingRunner;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Psr\EventDispatcher\EventDispatcherInterface;
use Predis\Client as PredisClient;

// Setup Redis cache
$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis);

// Setup infrastructure adapter
$htaccessAdapter = new ApacheHtaccessAdapter('/var/www/app/public/.htaccess');
$runner = new SyncNonBlockingRunner();

$infraListener = new InfrastructureBanListener(
    infrastructureBlocker: $htaccessAdapter,
    nonBlockingRunner: $runner,
    blockOnFail2Ban: true,
    blockOnBlocklist: false  // Only mirror Fail2Ban bans
);

// Create dispatcher that handles both logging and infrastructure
$dispatcher = new class ($infraListener) implements EventDispatcherInterface {
    public function __construct(private InfrastructureBanListener $infraListener) {}

    public function dispatch(object $event): object
    {
        // Log all events
        error_log('[Firewall] ' . $event::class);

        // Mirror bans to infrastructure
        if ($event instanceof Fail2BanBanned) {
            $this->infraListener->onFail2BanBanned($event);
        }
        if ($event instanceof BlocklistMatched) {
            $this->infraListener->onBlocklistMatched($event);
        }

        return $event;
    }
};

// Configure firewall
$config = new Config($cache, $dispatcher);

$config->fail2ban->add('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

$config->throttles->add('global', limit: 100, period: 60, key: KeyExtractors::ip());

// Create middleware
$middleware = new Middleware($config);

// When a login fails 5 times:
// 1. Phirewall bans the IP in Redis (application-level)
// 2. Fail2BanBanned event is dispatched
// 3. InfrastructureBanListener adds IP to .htaccess (server-level)
// 4. Subsequent requests blocked by Apache before reaching PHP
```

---

## Security Considerations

### File Permissions

Ensure the web server process can write to .htaccess:

```bash
chown www-data:www-data /var/www/app/.htaccess
chmod 644 /var/www/app/.htaccess
```

### Validate Input

Always validate IPs before passing to adapters:

```php
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    throw new InvalidArgumentException("Invalid IP: $ip");
}
```

### Rate Limit Infrastructure Updates

Don't update .htaccess on every request:

```php
// BAD - updates .htaccess on every block
$adapter->blockIp($ip);

// GOOD - batch updates periodically
$pendingBlocks[] = $ip;
if (count($pendingBlocks) >= 10 || $timeSinceLastFlush > 60) {
    $adapter->blockMany($pendingBlocks);
    $pendingBlocks = [];
}
```

### Test in Staging First

Infrastructure changes affect all traffic. Test thoroughly before production.

---

## Troubleshooting

### Apache: 403 Forbidden for All Requests

Check that the .htaccess syntax is correct:

```bash
apachectl configtest
```

### Apache: Require Directive Not Recognized

Ensure mod_authz_core is enabled:

```bash
a2enmod authz_core
systemctl restart apache2
```

### Permission Denied Writing .htaccess

Check ownership and permissions:

```bash
ls -la /var/www/app/.htaccess
# Should be writable by web server user
```

### IPv6 Addresses Not Blocking

Ensure Apache is configured for IPv6:

```apache
# In httpd.conf or apache2.conf
Listen 80
Listen [::]:80
```
