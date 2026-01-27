# Phirewall Documentation

Phirewall is a PHP-based application firewall providing PSR-15 middleware for protecting web applications against common attacks.

## Table of Contents

1. [Getting Started](getting-started.md)
2. [Common Web Attacks & Protection](common-attacks.md)
3. [Configuration Reference](configuration.md)
4. [Storage Backends](storage-backends.md)
5. [Pattern Backends](pattern-backends.md)
6. [OWASP Core Rule Set](owasp-crs.md)
7. [Observability & Events](observability.md)
8. [Infrastructure Adapters](infrastructure-adapters.md)

## Quick Links

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Executable Examples](../examples/)

## Installation

```bash
composer require flowd/phirewall
```

### Optional Dependencies

```bash
# For Redis-backed distributed counters
composer require predis/predis

# For APCu in-process counters (requires ext-apcu)
# Enable with: apc.enable_cli=1 for CLI testing
```

## Basic Usage

```php
<?php

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\KeyExtractors;

// 1. Create a cache backend
$cache = new InMemoryCache();

// 2. Configure the firewall
$config = new Config($cache);

// Allow health checks to bypass all rules
$config->safelist('health', fn($req) => $req->getUri()->getPath() === '/health');

// Block known malicious paths
$config->blocklist('admin-probe', fn($req) => str_starts_with($req->getUri()->getPath(), '/wp-admin'));

// Rate limit by IP: 100 requests per minute
$config->throttle('ip-limit', limit: 100, period: 60, key: KeyExtractors::ip());

// 3. Create the middleware
$middleware = new Middleware($config);

// 4. Add to your PSR-15 middleware stack
// $app->pipe($middleware);
```

## Features Overview

| Feature | Description |
|---------|-------------|
| **Safelists** | Bypass all checks for trusted requests (health checks, internal IPs) |
| **Blocklists** | Immediately deny suspicious requests (403 Forbidden) |
| **Throttling** | Rate limit requests per key with configurable windows (429 Too Many Requests) |
| **Fail2Ban** | Auto-ban after repeated failures (brute force protection) |
| **Track** | Passive counting for observability without blocking |
| **OWASP CRS** | Load and evaluate OWASP Core Rule Set rules |
| **Pattern Backends** | File/Redis-backed blocklists with IP/CIDR/path/header patterns |

## Rule Evaluation Order

Rules are evaluated in this order:

1. **Track** - Passive counters (no blocking)
2. **Safelist** - If matched, skip all remaining checks
3. **Blocklist** - If matched, return 403
4. **Fail2Ban** - Check ban status and increment failure counters
5. **Throttle** - Check rate limits, return 429 if exceeded

## Response Headers

When a request is blocked, the following headers are included:

| Header | Values | Description |
|--------|--------|-------------|
| `X-Phirewall` | `blocklist`, `throttle`, `fail2ban` | Block type |
| `X-Phirewall-Matched` | Rule name | Which rule triggered |
| `Retry-After` | Seconds | Time until throttle window resets (429 only) |

Optional headers (when enabled):

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Configured limit for the throttle rule |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Seconds until window resets |
| `X-Phirewall-Safelist` | Safelist rule name that matched |

## License

Dual licensed under LGPL-3.0-or-later and proprietary. See LICENSE file for details.
