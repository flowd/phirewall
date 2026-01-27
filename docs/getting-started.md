# Getting Started with Phirewall

This guide walks you through setting up Phirewall in your PHP application.

## Prerequisites

- PHP 8.2 or higher
- Composer
- A PSR-7/PSR-15 compatible application

## Installation

```bash
composer require flowd/phirewall
```

## Step 1: Choose a Storage Backend

Phirewall needs a PSR-16 cache for storing counters and ban states.

### In-Memory Cache (Development/Testing)

```php
use Flowd\Phirewall\Store\InMemoryCache;

$cache = new InMemoryCache();
```

### Redis (Production - Distributed)

```bash
composer require predis/predis
```

```php
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis, 'myapp:firewall:');
```

### APCu (Production - Single Server)

```php
use Flowd\Phirewall\Store\ApcuCache;

// Requires ext-apcu and apc.enable_cli=1 for CLI
$cache = new ApcuCache();
```

## Step 2: Create Configuration

```php
use Flowd\Phirewall\Config;

$config = new Config($cache);

// Optional: Set a key prefix to avoid collisions
$config->setKeyPrefix('myapp');
```

## Step 3: Define Rules

### Safelists (Allow Trusted Traffic)

```php
// Health check endpoint
$config->safelist('health', fn($req) => $req->getUri()->getPath() === '/health');

// Internal monitoring
$config->safelist('metrics', fn($req) => $req->getUri()->getPath() === '/metrics');
```

### Blocklists (Deny Malicious Traffic)

```php
// Block WordPress admin probes
$config->blocklist('wp-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/wp-admin'));

// Block phpMyAdmin probes
$config->blocklist('pma-probe', fn($req) => str_contains($req->getUri()->getPath(), 'phpmyadmin'));
```

### Throttling (Rate Limiting)

```php
use Flowd\Phirewall\KeyExtractors;

// 100 requests per minute per IP
$config->throttle('ip-minute', limit: 100, period: 60, key: KeyExtractors::ip());

// Enable standard rate limit headers
$config->enableRateLimitHeaders();
```

### Fail2Ban (Brute Force Protection)

```php
// Ban after 5 failed logins in 5 minutes, for 1 hour
$config->fail2ban('login-abuse',
    threshold: 5,
    period: 300,
    ban: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);
```

## Step 4: Create Middleware

```php
use Flowd\Phirewall\Middleware;

$middleware = new Middleware($config);
```

## Step 5: Add to Your Application

### Slim Framework

```php
$app->add($middleware);
```

### Laminas/Mezzio

```php
$app->pipe($middleware);
```

### Laravel (via PSR-15 Bridge)

```php
// In a service provider
$this->app->singleton(Middleware::class, function ($app) {
    $cache = new RedisCache($app->make('redis'));
    $config = new Config($cache);
    // ... configure rules
    return new Middleware($config);
});
```

## Complete Example

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// 1. Setup cache
$cache = new InMemoryCache();

// 2. Configure firewall
$config = new Config($cache);
$config->setKeyPrefix('demo');
$config->enableRateLimitHeaders();

// Safelist health endpoint
$config->safelist('health', fn($req) => $req->getUri()->getPath() === '/health');

// Block suspicious paths
$config->blocklist('wp-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/wp-'));

// Rate limit: 10 requests per minute per IP
$config->throttle('ip-limit', limit: 10, period: 60, key: KeyExtractors::ip());

// Fail2Ban: 3 failures in 2 minutes = 5 minute ban
$config->fail2ban('login',
    threshold: 3,
    period: 120,
    ban: 300,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

// 3. Create middleware
$middleware = new Middleware($config, new Psr17Factory());

// 4. Your application handler
$handler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'text/plain'], "Hello, World!\n");
    }
};

// 5. Process a request
$request = new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => '192.168.1.100']);
$response = $middleware->process($request, $handler);

echo "Status: " . $response->getStatusCode() . "\n";
```

## Next Steps

- Learn about [Common Web Attacks & Protection](common-attacks.md)
- Explore the [Configuration Reference](configuration.md)
- Set up [Observability & Events](observability.md)
