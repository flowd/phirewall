# Common Web Attacks & Protection

This guide covers the most common web attacks and how to configure Phirewall to protect against them.

## Table of Contents

1. [Brute Force Attacks](#1-brute-force-attacks)
2. [Credential Stuffing](#2-credential-stuffing)
3. [DDoS & Rate Abuse](#3-ddos--rate-abuse)
4. [SQL Injection](#4-sql-injection)
5. [Cross-Site Scripting (XSS)](#5-cross-site-scripting-xss)
6. [Path Traversal](#6-path-traversal)
7. [Remote Code Execution (RCE)](#7-remote-code-execution-rce)
8. [Scanner & Bot Detection](#8-scanner--bot-detection)
9. [API Abuse](#9-api-abuse)
10. [Session Hijacking Prevention](#10-session-hijacking-prevention)

---

## 1. Brute Force Attacks

### Attack Description

Attackers repeatedly try username/password combinations to gain unauthorized access. Common targets include login forms, admin panels, and API authentication endpoints.

### Protection Strategy

Use **Fail2Ban** to automatically ban IPs after repeated failed attempts, combined with **Throttling** to slow down attempts.

### Configuration

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\RedisCache;

$config = new Config($cache);

// Strategy 1: Ban after 5 failed logins in 5 minutes
// Your application should set X-Login-Failed header on auth failure
$config->fail2ban->add('login-brute-force',
    threshold: 5,      // Max failures before ban
    period: 300,       // 5 minute observation window
    ban: 3600,         // 1 hour ban
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);

// Strategy 2: Additionally throttle login attempts
$config->throttles->add('login-rate',
    limit: 10,         // Max 10 login attempts
    period: 60,        // Per minute
    key: function ($req): ?string {
        $path = $req->getUri()->getPath();
        if ($path === '/login' || $path === '/api/auth') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null; // Skip non-login requests
    }
);

// Strategy 3: Track failed logins for observability
$config->tracks->add('login-failures',
    period: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::ip()
);
```

### Application Integration

Your application signals a failed login by setting a request attribute that Phirewall can check. The simplest approach is to use a request header or attribute set by your authentication middleware:

```php
// In your login controller
public function login(Request $request): Response
{
    $user = $this->authenticate($request->get('username'), $request->get('password'));

    if (!$user) {
        return (new Response(401))
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('X-Login-Failed', '1');
    }

    // Successful login...
}
```


---

## 2. Credential Stuffing

### Attack Description

Attackers use lists of stolen username/password combinations from data breaches to attempt logins across multiple services.

### Protection Strategy

Combine IP-based and user-based throttling with Fail2Ban to detect distributed attacks.

### Configuration

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;

// Per-IP rate limiting
$config->fail2ban->add('credential-stuffing-ip',
    threshold: 10,
    period: 600,       // 10 minute window
    ban: 7200,         // 2 hour ban
    filter: fn($req) => $req->getUri()->getPath() === '/login',
    key: KeyExtractors::ip()
);

// Per-username rate limiting (extract from POST body)
$config->throttles->add('credential-stuffing-user',
    limit: 5,
    period: 300,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() !== '/login') {
            return null;
        }
        // Parse POST body for username
        $body = (array) $req->getParsedBody();
        $username = $body['username'] ?? $body['email'] ?? null;
        return $username ? 'user:' . strtolower(trim($username)) : null;
    }
);

// Detect rapid-fire attempts (burst detection)
$config->throttles->add('login-burst',
    limit: 3,          // Only 3 attempts
    period: 10,        // In 10 seconds
    key: function ($req): ?string {
        if ($req->getMethod() === 'POST' && $req->getUri()->getPath() === '/login') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);
```

---

## 3. DDoS & Rate Abuse

### Attack Description

Attackers flood your application with requests to overwhelm resources. This includes:
- HTTP flood attacks
- Slowloris attacks
- Application-layer DDoS

### Protection Strategy

Implement tiered rate limiting: global limits, per-endpoint limits, and burst detection.

### Configuration

```php
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;

// Configure trusted proxies for accurate IP detection
$proxyResolver = new TrustedProxyResolver([
    '127.0.0.1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);

// Tier 1: Global per-IP limit
$config->throttles->add('global-ip',
    limit: 1000,       // 1000 requests
    period: 60,        // Per minute
    key: KeyExtractors::clientIp($proxyResolver)
);

// Tier 2: Stricter limit for write operations
$config->throttles->add('write-operations',
    limit: 100,
    period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        $method = $req->getMethod();
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

// Tier 3: Burst detection (sudden spike)
$config->throttles->add('burst-detection',
    limit: 50,
    period: 5,         // 50 requests in 5 seconds = likely attack
    key: KeyExtractors::clientIp($proxyResolver)
);

// Tier 4: Per-endpoint limits for expensive operations
$config->throttles->add('search-endpoint',
    limit: 20,
    period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        if ($req->getUri()->getPath() === '/api/search') {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

// Enable rate limit headers for client awareness
$config->enableRateLimitHeaders();
```

---

## 4. SQL Injection

### Attack Description

Attackers inject malicious SQL through user inputs to manipulate database queries.

### Protection Strategy

Use OWASP Core Rule Set (CRS) patterns to detect SQL injection attempts.

### Configuration

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

// Load OWASP CRS rules for SQL injection detection
$sqlRules = <<<'RULES'
# SQL Injection - Basic patterns
SecRule ARGS "@rx (?i)(\b(union|select|insert|update|delete|drop|alter)\b.*\b(from|into|table|database)\b)" \
    "id:942100,phase:2,deny,msg:'SQL Injection Attack Detected'"

# SQL Injection - Comment sequences
SecRule ARGS "@rx (?i)(--|#|/\*|\*/|;)" \
    "id:942110,phase:2,deny,msg:'SQL Comment Injection'"

# SQL Injection - Hex encoding
SecRule ARGS "@rx (?i)0x[0-9a-f]+" \
    "id:942120,phase:2,deny,msg:'SQL Hex Encoding Detected'"

# SQL Injection - UNION attacks
SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" \
    "id:942130,phase:2,deny,msg:'SQL UNION Attack'"

# SQL Injection - Quote manipulation
SecRule ARGS "@rx ('|\")\s*(or|and)\s*('|\"|[0-9])" \
    "id:942140,phase:2,deny,msg:'SQL Quote Injection'"
RULES;

$coreRuleSet = SecRuleLoader::fromString($sqlRules);
$config->blocklists->owasp('sql-injection', $coreRuleSet);

// Optional: Enable diagnostics header for debugging
// $config->enableOwaspDiagnosticsHeader();
```

### Alternative: Pattern-Based Blocklist

```php
$config->blocklists->add('sql-injection', function ($req): bool {
    $patterns = [
        '/union\s+select/i',
        '/select\s+.*\s+from/i',
        '/insert\s+into/i',
        '/drop\s+table/i',
        '/--\s*$/m',
        '/;\s*drop/i',
        '/\'\s*or\s*\'1\'\s*=\s*\'1/i',
        '/\'\s*or\s+1\s*=\s*1/i',
    ];

    $queryString = $req->getUri()->getQuery();
    $body = (string) $req->getBody();
    $input = $queryString . ' ' . $body;

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }

    return false;
});
```

---

## 5. Cross-Site Scripting (XSS)

### Attack Description

Attackers inject malicious scripts into web pages viewed by other users.

### Protection Strategy

Detect common XSS patterns in request parameters using OWASP rules.

### Configuration

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

$xssRules = <<<'RULES'
# XSS - Script tags
SecRule ARGS "@rx (?i)<script[^>]*>.*?</script>" \
    "id:941100,phase:2,deny,msg:'XSS Script Tag Detected'"

# XSS - Event handlers
SecRule ARGS "@rx (?i)\bon\w+\s*=\s*['\"][^'\"]*['\"]" \
    "id:941110,phase:2,deny,msg:'XSS Event Handler Detected'"

# XSS - JavaScript protocol
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS JavaScript Protocol'"

# XSS - Data URI
SecRule ARGS "@rx (?i)data\s*:\s*[^,]*;base64" \
    "id:941130,phase:2,deny,msg:'XSS Data URI Detected'"

# XSS - SVG/XML attacks
SecRule ARGS "@rx (?i)<svg[^>]*onload" \
    "id:941140,phase:2,deny,msg:'XSS SVG Attack'"

# XSS - Encoded attacks
SecRule ARGS "@rx (?i)(&#x?[0-9a-f]+;?){3,}" \
    "id:941150,phase:2,deny,msg:'XSS HTML Entity Encoding'"
RULES;

$coreRuleSet = SecRuleLoader::fromString($xssRules);
$config->blocklists->owasp('xss-attacks', $coreRuleSet);
```

---

## 6. Path Traversal

### Attack Description

Attackers attempt to access files outside the intended directory using `../` sequences.

### Protection Strategy

Block requests containing path traversal patterns.

### Configuration

```php
$config->blocklists->add('path-traversal', function ($req): bool {
    $path = $req->getUri()->getPath();
    $query = $req->getUri()->getQuery();
    $input = urldecode($path . '?' . $query);

    $patterns = [
        '/\.\.\//',                    // ../
        '/\.\.\\\\/',                  // ..\
        '/%2e%2e%2f/i',               // URL encoded ../
        '/%2e%2e%5c/i',               // URL encoded ..\
        '/\.\.\%00/',                  // Null byte injection
        '/etc\/passwd/',               // Common target
        '/etc\/shadow/',
        '/proc\/self/',
        '/windows\/system32/i',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }

    return false;
});
```

---

## 7. Remote Code Execution (RCE)

### Attack Description

Attackers attempt to execute arbitrary code on the server through various injection techniques.

### Protection Strategy

Use OWASP CRS PHP attack rules to detect common RCE patterns.

### Configuration

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

$rceRules = <<<'RULES'
# PHP Code Injection - Function calls
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(" \
    "id:933100,phase:2,deny,msg:'PHP Code Injection Detected'"

# PHP Code Injection - Dangerous functions
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(" \
    "id:933110,phase:2,deny,msg:'PHP Obfuscation Function'"

# PHP Code Injection - Variable functions
SecRule ARGS "@rx \$\{.*\}" \
    "id:933120,phase:2,deny,msg:'PHP Variable Function Call'"

# Command Injection - Shell metacharacters
SecRule ARGS "@rx [;|&`$]" \
    "id:933130,phase:2,deny,msg:'Command Injection Metacharacter'"

# PHP Code Injection - Include/require
SecRule ARGS "@rx (?i)(include|require)(_once)?\s*\(" \
    "id:933140,phase:2,deny,msg:'PHP Include Injection'"
RULES;

$coreRuleSet = SecRuleLoader::fromString($rceRules);
$config->blocklists->owasp('rce-attacks', $coreRuleSet);
```

---

## 8. Scanner & Bot Detection

### Attack Description

Automated scanners and malicious bots probe for vulnerabilities, consuming resources and potentially finding weaknesses.

### Protection Strategy

Block known scanner signatures and suspicious patterns.

### Configuration

```php
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

// Pattern-based bot blocking
$patternBackend = $config->blocklists->filePatternBackend('bots', '/var/lib/phirewall/bots.txt');

// Block known scanner User-Agents
$patternBackend->append(new PatternEntry(
    kind: PatternKind::HEADER_REGEX,
    value: '/sqlmap|nikto|nmap|masscan|burp|dirbuster|gobuster|wfuzz/i',
    target: 'User-Agent',
));

// Block empty User-Agents (often bots)
$patternBackend->append(new PatternEntry(
    kind: PatternKind::HEADER_EXACT,
    value: '',
    target: 'User-Agent',
));

$config->blocklists->fromBackend('scanner-bots', 'bots');

// Block common scanner paths
$config->blocklists->add('scanner-paths', function ($req): bool {
    $scannerPaths = [
        '/wp-admin',
        '/wp-login.php',
        '/wp-content/plugins',
        '/phpmyadmin',
        '/pma',
        '/admin.php',
        '/administrator',
        '/.env',
        '/.git',
        '/.svn',
        '/config.php',
        '/phpinfo.php',
        '/server-status',
        '/elmah.axd',
        '/web.config',
        '/.htaccess',
        '/.htpasswd',
        '/backup',
        '/db.sql',
        '/dump.sql',
    ];

    $path = strtolower($req->getUri()->getPath());

    foreach ($scannerPaths as $scannerPath) {
        if (str_starts_with($path, $scannerPath)) {
            return true;
        }
    }

    return false;
});

// Ban persistent scanners
$config->fail2ban->add('persistent-scanner',
    threshold: 10,     // 10 blocked requests
    period: 60,        // In 1 minute
    ban: 86400,        // 24 hour ban
    filter: fn($req) => true, // Applied to all blocked requests
    key: KeyExtractors::ip()
);
```

---

## 9. API Abuse

### Attack Description

Attackers abuse API endpoints through:
- Excessive requests (scraping)
- Parameter manipulation
- Enumeration attacks

### Protection Strategy

Implement per-endpoint, per-user, and per-action rate limits.

### Configuration

```php
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Http\TrustedProxyResolver;

$proxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);

// Authenticated user limits (higher)
$config->throttles->add('api-user',
    limit: 1000,
    period: 3600,      // Per hour
    key: KeyExtractors::header('X-User-Id')
);

// Anonymous/API key limits (lower)
$config->throttles->add('api-anon',
    limit: 100,
    period: 3600,
    key: function ($req) use ($proxyResolver): ?string {
        // Only apply if no authenticated user
        if ($req->getHeaderLine('X-User-Id') !== '') {
            return null;
        }
        return $proxyResolver->resolve($req);
    }
);

// Expensive endpoint limits
$config->throttles->add('api-export',
    limit: 10,
    period: 3600,
    key: function ($req): ?string {
        if (str_starts_with($req->getUri()->getPath(), '/api/export')) {
            return $req->getHeaderLine('X-User-Id') ?: $req->getServerParams()['REMOTE_ADDR'];
        }
        return null;
    }
);

// User enumeration protection
$config->throttles->add('user-lookup',
    limit: 30,
    period: 60,
    key: function ($req) use ($proxyResolver): ?string {
        $path = $req->getUri()->getPath();
        if (preg_match('#^/api/users/\d+$#', $path)) {
            return $proxyResolver->resolve($req);
        }
        return null;
    }
);

// Password reset abuse
$config->throttles->add('password-reset',
    limit: 3,
    period: 3600,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() === '/api/password-reset' && $req->getMethod() === 'POST') {
            $body = (array) $req->getParsedBody();
            return $body['email'] ?? null;
        }
        return null;
    }
);
```

---

## 10. Session Hijacking Prevention

### Attack Description

Attackers steal or predict session tokens to impersonate legitimate users.

### Protection Strategy

Detect suspicious session activity patterns.

### Configuration

```php
use Flowd\Phirewall\KeyExtractors;

// Detect concurrent sessions from different IPs
$config->tracks->add('session-ip-change',
    period: 3600,
    filter: function ($req): bool {
        // Check if session IP changed
        return $req->getHeaderLine('X-Session-IP-Changed') === '1';
    },
    key: KeyExtractors::header('X-Session-Id')
);

// Rate limit session creation
$config->throttles->add('session-creation',
    limit: 10,
    period: 300,
    key: function ($req): ?string {
        if ($req->getUri()->getPath() === '/api/sessions' && $req->getMethod() === 'POST') {
            return $req->getServerParams()['REMOTE_ADDR'] ?? null;
        }
        return null;
    }
);

// Block session fixation attempts
$config->blocklists->add('session-fixation', function ($req): bool {
    // Block if session ID is in URL
    $query = $req->getUri()->getQuery();
    return preg_match('/(?:PHPSESSID|sessionid|sid|session_id)=/i', $query) === 1;
});
```

---

## Combined Configuration Example

Here's a comprehensive configuration combining all attack protections:

```php
<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client as PredisClient;

// Production setup with Redis
$redis = new PredisClient(getenv('REDIS_URL') ?: 'redis://localhost:6379');
$cache = new RedisCache($redis, 'myapp:fw:');

$config = new Config($cache);
$config->setKeyPrefix('prod');
$config->enableRateLimitHeaders();

// Trusted proxy configuration
$proxyResolver = new TrustedProxyResolver([
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]);

// === SAFELISTS ===
$config->safelists->add('health', fn($req) => $req->getUri()->getPath() === '/health');
$config->safelists->add('metrics', fn($req) => $req->getUri()->getPath() === '/metrics');

// === BLOCKLISTS ===

// Scanner paths
$config->blocklists->add('scanners', function ($req): bool {
    $blocked = ['/wp-admin', '/phpmyadmin', '/.env', '/.git', '/phpinfo.php'];
    $path = strtolower($req->getUri()->getPath());
    foreach ($blocked as $p) {
        if (str_starts_with($path, $p)) return true;
    }
    return false;
});

// Path traversal
$config->blocklists->add('path-traversal', function ($req): bool {
    $input = urldecode($req->getUri()->getPath() . '?' . $req->getUri()->getQuery());
    return preg_match('~\.\.[\\\\/]~', $input) === 1;
});

// === OWASP RULES ===
$owaspRules = SecRuleLoader::fromDirectory(__DIR__ . '/owasp-rules');
$config->blocklists->owasp('owasp', $owaspRules);

// === FAIL2BAN ===
$config->fail2ban->add('login-brute',
    threshold: 5, period: 300, ban: 3600,
    filter: fn($req) => $req->getHeaderLine('X-Login-Failed') === '1',
    key: KeyExtractors::clientIp($proxyResolver)
);

// === THROTTLES ===
$config->throttles->add('global', limit: 1000, period: 60, key: KeyExtractors::clientIp($proxyResolver));
$config->throttles->add('write-ops', limit: 100, period: 60, key: function ($req) use ($proxyResolver): ?string {
    if (in_array($req->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
        return $proxyResolver->resolve($req);
    }
    return null;
});
$config->throttles->add('login', limit: 10, period: 60, key: function ($req) use ($proxyResolver): ?string {
    if ($req->getUri()->getPath() === '/login') {
        return $proxyResolver->resolve($req);
    }
    return null;
});
```

---

## Testing Your Configuration

Run the included examples to verify protection:

```bash
# Test rate limiting
php examples/03-api-rate-limiting.php

# Test login protection
php examples/02-brute-force-protection.php

# Test OWASP rules
php examples/04-sql-injection-blocking.php

# Test comprehensive protection
php examples/08-comprehensive-protection.php
```

## Next Steps

- Configure [Observability & Events](observability.md) to monitor blocked attacks
- Set up [Infrastructure Adapters](infrastructure-adapters.md) for server-level blocking
- Review the [Configuration Reference](configuration.md) for all options
