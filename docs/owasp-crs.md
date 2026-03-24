# OWASP Core Rule Set Integration

Phirewall can parse and evaluate a subset of the OWASP Core Rule Set (CRS) to detect common web attacks using familiar `SecRule` syntax.

## Overview

The OWASP CRS adapter provides:
- Parsing of `SecRule` directives
- Support for common operators and variables
- Rule enable/disable control
- Integration with Phirewall blocklists

**Note:** This is not a full CRS implementation. It supports a practical subset suitable for most use cases.

---

## Quick Start

### Loading Rules from a String

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;

$rules = <<<'CRS'
SecRule REQUEST_URI "@rx /admin" "id:1001,phase:2,deny,msg:'Block admin access'"
SecRule ARGS "@contains <script>" "id:1002,phase:2,deny,msg:'XSS Detected'"
CRS;

$coreRuleSet = SecRuleLoader::fromString($rules);

$config = new Config(new InMemoryCache());
$config->blocklists->owasp('custom-rules', $coreRuleSet);
```

### Loading Rules from Files

```php
use Flowd\Phirewall\Owasp\SecRuleLoader;

// Single file
$crs = SecRuleLoader::fromFile('/path/to/rules.conf');

// Multiple files
$crs = SecRuleLoader::fromFiles([
    '/path/to/sql-injection.conf',
    '/path/to/xss.conf',
]);

// Directory (all files — use a filter to restrict to .conf)
$crs = SecRuleLoader::fromDirectory('/path/to/crs/rules');

// Directory with filter
$crs = SecRuleLoader::fromDirectory('/path/to/crs/rules',
    fn($path) => str_ends_with($path, '.conf') && !str_contains($path, 'test')
);
```

---

## Supported Variables

| Variable | Description |
|----------|-------------|
| `REQUEST_URI` | Path and query string combined |
| `REQUEST_METHOD` | HTTP method (GET, POST, etc.) |
| `QUERY_STRING` | Query string only |
| `ARGS` | All argument names and values (query + body) |
| `ARGS_NAMES` | Argument names only |
| `REQUEST_HEADERS` | All header values |
| `REQUEST_HEADERS_NAMES` | Header names only |
| `REQUEST_COOKIES` | Cookie values |
| `REQUEST_COOKIES_NAMES` | Cookie names |

**Note:** Unsupported variables cause the rule to be skipped (no match).

---

## Supported Operators

### String Operators (case-insensitive)

| Operator | Description | Example |
|----------|-------------|---------|
| `@contains` | Substring match | `@contains admin` |
| `@streq` | Exact string match | `@streq POST` |
| `@startswith` | Prefix match | `@startswith /api/` |
| `@beginswith` | Alias for startswith | `@beginswith /api/` |
| `@endswith` | Suffix match | `@endswith .php` |

### Pattern Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `@rx` | Perl-compatible regex | `@rx ^/admin\b` |
| `@pm` | Phrase match (list) | `@pm select union insert` |
| `@pmFromFile` | Phrases from file | `@pmFromFile sql-keywords.txt` |

---

## Rule Syntax

### Basic Format

```
SecRule VARIABLE "OPERATOR PATTERN" "id:NUMBER,phase:N,ACTION,msg:'MESSAGE'"
```

### Examples

```apache
# Block requests to /admin
SecRule REQUEST_URI "@rx ^/admin" \
    "id:100001,phase:2,deny,msg:'Admin access blocked'"

# Block SQL injection attempts
SecRule ARGS "@rx (?i)(union\s+select|select\s+.*\s+from)" \
    "id:100002,phase:2,deny,msg:'SQL Injection Detected'"

# Block XSS in any header
SecRule REQUEST_HEADERS "@contains <script>" \
    "id:100003,phase:2,deny,msg:'XSS in header'"

# Block specific User-Agent
SecRule REQUEST_HEADERS:User-Agent "@pm nikto sqlmap nmap" \
    "id:100004,phase:2,deny,msg:'Scanner detected'"
```

### Multi-line Rules

Use backslash for continuation:

```apache
SecRule REQUEST_URI "@rx ^/admin" \
    "id:100001,\
     phase:2,\
     deny,\
     msg:'Admin access blocked'"
```

---

## Phrase Match Files

Use `@pmFromFile` to load patterns from external files:

### Rule Definition

```apache
SecRule ARGS "@pmFromFile sql-keywords.data" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
```

### File Format (sql-keywords.data)

```
select
union
insert
delete
drop
# Comments start with hash
update
alter
```

**Limits:**
- Maximum 5000 phrases per file
- Phrases beyond the limit are ignored

---

## Managing Rules

### Enable/Disable Rules

```php
$crs = \Flowd\Phirewall\Owasp\SecRuleLoader::fromDirectory('/path/to/rules');

// Disable specific rules
$crs->disable(942100);  // SQL injection rule
$crs->disable(941100);  // XSS rule

// Re-enable a rule
$crs->enable(942100);

// Check if enabled
if ($crs->isEnabled(942100)) {
    echo "Rule 942100 is active\n";
}
```

### List All Rules

```php
foreach ($crs->ids() as $id) {
    $status = $crs->isEnabled($id) ? 'enabled' : 'disabled';
    echo "Rule $id: $status\n";
}
```

### Get Rule Details

```php
$rule = $crs->getRule(942100);
if ($rule) {
    echo "ID: " . $rule->id . "\n";
    // Access other rule properties...
}
```

---

## Loading Statistics

Get information about parsed rules:

```php
$result = \Flowd\Phirewall\Owasp\SecRuleLoader::fromStringWithReport($rulesText);

echo "Parsed: " . $result['parsed'] . " rules\n";
echo "Skipped: " . $result['skipped'] . " lines\n";

$crs = $result['rules'];
```

---

## Diagnostics Header

Enable diagnostics to see which rule blocked a request:

```php
$config->enableOwaspDiagnosticsHeader(true);
```

**Response header when blocked:**
```
X-Phirewall-Owasp-Rule: 942100
```

**Warning:** Only enable in development/debugging. Reveals rule information to attackers.

---

## Pre-built Rule Sets

### SQL Injection

```php
$sqlRules = <<<'CRS'
# SQL Injection - Basic
SecRule ARGS "@rx (?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b)" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"

# SQL Injection - Comments
SecRule ARGS "@rx (--|#|/\*)" \
    "id:942110,phase:2,deny,msg:'SQL Comment Injection'"

# SQL Injection - Quotes
SecRule ARGS "@rx ('\s*(or|and)\s*'|'\s*=\s*')" \
    "id:942120,phase:2,deny,msg:'SQL Quote Injection'"

# SQL Injection - Hex
SecRule ARGS "@rx 0x[0-9a-f]{2,}" \
    "id:942130,phase:2,deny,msg:'SQL Hex Encoding'"
CRS;
```

### XSS Prevention

```php
$xssRules = <<<'CRS'
# XSS - Script tags
SecRule ARGS "@rx (?i)<script[^>]*>" \
    "id:941100,phase:2,deny,msg:'XSS Script Tag'"

# XSS - Event handlers
SecRule ARGS "@rx (?i)\bon\w+\s*=" \
    "id:941110,phase:2,deny,msg:'XSS Event Handler'"

# XSS - JavaScript protocol
SecRule ARGS "@rx (?i)javascript\s*:" \
    "id:941120,phase:2,deny,msg:'XSS JavaScript Protocol'"

# XSS - Data URI
SecRule ARGS "@rx (?i)data\s*:[^,]*;base64" \
    "id:941130,phase:2,deny,msg:'XSS Data URI'"
CRS;
```

### PHP Injection

```php
$phpRules = <<<'CRS'
# PHP - Dangerous functions
SecRule ARGS "@rx (?i)(eval|exec|system|shell_exec|passthru)\s*\(" \
    "id:933100,phase:2,deny,msg:'PHP Code Injection'"

# PHP - Obfuscation
SecRule ARGS "@rx (?i)(base64_decode|gzinflate|str_rot13)\s*\(" \
    "id:933110,phase:2,deny,msg:'PHP Obfuscation'"

# PHP - Variable functions
SecRule ARGS "@rx \$\{.*\}" \
    "id:933120,phase:2,deny,msg:'PHP Variable Function'"
CRS;
```

### Path Traversal

```php
$pathRules = <<<'CRS'
# Path Traversal - Basic
SecRule REQUEST_URI "@rx \.\./" \
    "id:930100,phase:2,deny,msg:'Path Traversal'"

# Path Traversal - Encoded
SecRule REQUEST_URI "@rx (?i)(%2e%2e%2f|%2e%2e/|\.%2e/|%2e\.\/)" \
    "id:930110,phase:2,deny,msg:'Encoded Path Traversal'"

# Path Traversal - Null byte
SecRule REQUEST_URI "@rx %00" \
    "id:930120,phase:2,deny,msg:'Null Byte Injection'"
CRS;
```

---

## Complete Example

```php
<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Owasp\SecRuleLoader;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

require __DIR__ . '/vendor/autoload.php';

// Load rules
$rules = <<<'CRS'
SecRule ARGS "@rx (?i)union\s+select" "id:942100,phase:2,deny,msg:'SQL Injection'"
SecRule ARGS "@rx (?i)<script" "id:941100,phase:2,deny,msg:'XSS Attack'"
SecRule REQUEST_URI "@rx \.\./" "id:930100,phase:2,deny,msg:'Path Traversal'"
CRS;

$coreRuleSet = SecRuleLoader::fromString($rules);

// Configure firewall
$config = new Config(new InMemoryCache());
$config->blocklists->owasp('owasp', $coreRuleSet);
$config->enableOwaspDiagnosticsHeader(); // For debugging

$firewall = new Firewall($config);

// Test requests
$tests = [
    new ServerRequest('GET', '/search?q=test'),                    // Safe
    new ServerRequest('GET', '/search?q=union+select+*'),          // SQL Injection
    new ServerRequest('GET', '/page?name=<script>alert(1)'),       // XSS
    new ServerRequest('GET', '/files/../../../etc/passwd'),        // Path Traversal
];

foreach ($tests as $request) {
    $result = $firewall->decide($request);
    $uri = (string) $request->getUri();

    if ($result->isBlocked()) {
        $ruleId = $result->headers['X-Phirewall-Owasp-Rule'] ?? 'n/a';
        echo "BLOCKED: $uri (Rule: $ruleId)\n";
    } else {
        echo "ALLOWED: $uri\n";
    }
}
```

**Output:**
```
ALLOWED: /search?q=test
BLOCKED: /search?q=union+select+* (Rule: 942100)
BLOCKED: /page?name=<script>alert(1) (Rule: 941100)
BLOCKED: /files/../../../etc/passwd (Rule: 930100)
```

---

## Safety Features

### Invalid Regex Handling

Invalid `@rx` patterns are treated as non-matches without throwing errors:

```apache
# This rule won't crash - just silently won't match
SecRule ARGS "@rx [invalid(regex" "id:1,phase:2,deny"
```

### Phrase Limits

`@pm` and `@pmFromFile` enforce a 5000 phrase limit to prevent memory issues.

### Evaluation Short-Circuit

Rules stop evaluating on first match for performance.

---

## Best Practices

1. **Start Permissive:** Begin with minimal rules and add more as needed
2. **Test Thoroughly:** Use your application's test suite with rules enabled
3. **Monitor False Positives:** Enable logging before blocking
4. **Disable Diagnostics in Production:** Never expose rule IDs to attackers
5. **Version Control Rules:** Keep rule files in source control
6. **Regular Updates:** Review and update rules periodically

---

## Resources

- [OWASP Core Rule Set](https://coreruleset.org/)
- [CRS Documentation](https://coreruleset.org/docs/)
- [ModSecurity Reference](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)
