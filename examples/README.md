# Phirewall Examples

This directory contains executable examples demonstrating various features of Phirewall.

## Running Examples

All examples can be run from the project root:

```bash
php examples/01-basic-setup.php
```

## Example Index

### Getting Started

| Example | Description |
|---------|-------------|
| [01-basic-setup.php](01-basic-setup.php) | Minimal configuration with safelist, blocklist, and throttle |

### Attack Protection

| Example | Description |
|---------|-------------|
| [02-brute-force-protection.php](02-brute-force-protection.php) | Fail2Ban and throttling for login protection |
| [03-api-rate-limiting.php](03-api-rate-limiting.php) | Tiered rate limiting for APIs |
| [04-sql-injection-blocking.php](04-sql-injection-blocking.php) | OWASP-style SQL injection detection |
| [05-xss-prevention.php](05-xss-prevention.php) | Cross-Site Scripting (XSS) detection |
| [06-bot-detection.php](06-bot-detection.php) | Scanner and malicious bot blocking |
| [07-ip-blocklist.php](07-ip-blocklist.php) | File-backed IP/CIDR/path blocklists |
| [08-comprehensive-protection.php](08-comprehensive-protection.php) | Production-ready multi-layer protection |

### Observability

| Example | Description |
|---------|-------------|
| [09-observability-monolog.php](09-observability-monolog.php) | Event logging with Monolog |
| [10-observability-opentelemetry.php](10-observability-opentelemetry.php) | Distributed tracing with OpenTelemetry |

### Storage Backends

| Example | Description |
|---------|-------------|
| [11-redis-storage.php](11-redis-storage.php) | Redis backend for multi-server deployments |
| [13-benchmarks.php](13-benchmarks.php) | Performance comparison of storage backends |

### Infrastructure

| Example | Description                                                                     |
|---------|---------------------------------------------------------------------------------|
| [12-apache-htaccess.php](12-apache-htaccess.php) | Apache .htaccess IP blocking integration                                        |
| [14-owasp-crs-files.php](14-owasp-crs-files.php) | Loading OWASP CRS rules from files in [14-owasp_crs_basic/](14-owasp_crs_basic/) |
| [15-in-memory-pattern-backend.php](15-in-memory-pattern-backend.php) | Configuration-based blocklists without file I/O                                 |

## Optional Dependencies

Some examples require optional dependencies:

```bash
# For Redis examples
composer require predis/predis

# For Monolog examples
composer require monolog/monolog

# For OpenTelemetry examples
composer require open-telemetry/sdk
```

## Quick Start

1. **Basic protection** - Start with `01-basic-setup.php` to understand the fundamentals.

2. **API protection** - Use `03-api-rate-limiting.php` as a template for API rate limiting.

3. **Full protection** - Use `08-comprehensive-protection.php` as a starting point for production deployments.

## Example Output

Each example produces formatted output showing:
- Configuration steps
- Request simulation results
- Diagnostics and statistics

Example output from `01-basic-setup.php`:

```
=== Phirewall Basic Setup Example ===

1. Cache backend created (InMemoryCache)
2. Configuration created with prefix 'demo'
3a. Safelist rule added: health endpoint
3b. Blocklist rule added: WordPress probes
3c. Throttle rule added: 5 requests/minute per IP
4. Middleware created

=== Request Simulation ===

Test 1: Health check endpoint (safelisted)
  GET /health                              => 200
    X-Phirewall-Safelist: health

Test 2: WordPress admin probe (blocklisted)
  GET /wp-admin/admin.php                  => 403
    X-Phirewall: blocked
    X-Phirewall-Matched: wp-probe

...
```

## Documentation

For complete documentation, see the [docs/](../docs/) directory.
