<?php

declare(strict_types=1);

/**
 * Example 31: Presets - ready-to-use rule bundles for common scenarios.
 *
 * Presets package universal protection rules (scanner blocking, sensitive-path
 * probing) so you do not hand-write them each time. Each preset is defined
 * internally as a PortableConfig (plain, inspectable, serializable data) and
 * exposed as an accessor, e.g.:
 *
 *   Presets::scannerBlocking()                 -> the underlying PortableConfig
 *
 * Apply a preset onto a cache with Config::with(); the result is a live Config
 * that layers with your own rules through the same Config::with() (see example
 * 30). Every rule is namespaced `preset.<area>.*`, so overriding one by name is
 * predictable.
 *
 * Presets cover only signals that are universal across applications. Rules that
 * depend on your own routing (API rate limiting on your API prefix, a throttle
 * and brute-force ban on your login path) are a few lines of plain Config; see
 * examples 03-api-rate-limiting.php and 02-brute-force-protection.php.
 *
 * This example:
 *   1. uses a preset standalone;
 *   2. inspects/serializes the underlying PortableConfig;
 *   3. composes presets with a user Config, overriding a rule BY NAME;
 *   4. shows Presets::VERSION and how an integrator compares it against their
 *      own feed with version_compare() (Phirewall ships no update mechanism and
 *      performs no network I/O).
 *
 * Run: php examples/31-presets.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Presets ===\n\n";

$cache = new InMemoryCache();

// ─────────────────────────────────────────────────────────────────────────
// 1. A preset standalone.
// ─────────────────────────────────────────────────────────────────────────
echo "1. Scanner-blocking preset, used as-is:\n";
$scannerFirewall = new Firewall((new Config($cache))->with(Presets::scannerBlocking()));

assertDecision(
    $scannerFirewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'),
    'blocked',
    'known scanner User-Agent (preset.scanner.known-tools)',
);
assertDecision(
    $scannerFirewall,
    new ServerRequest('GET', '/'), // no Accept-* headers
    'blocked',
    'missing standard browser headers (preset.scanner.suspicious-headers)',
);
assertDecision(
    $scannerFirewall,
    browserRequest('GET', '/'),
    'pass',
    'a normal browser request passes',
);

// ─────────────────────────────────────────────────────────────────────────
// 2. Presets are inspectable, serializable data.
// ─────────────────────────────────────────────────────────────────────────
echo "\n2. The same preset as portable data (serialize / diff / sign):\n";
$portable = Presets::scannerBlocking();
$schema = $portable->toArray();
printf("   blocklist rules: %s\n", implode(', ', array_column($schema['blocklists'], 'name')));

// Round-trips like any PortableConfig (JSON, signed transport, ...).
$json = json_encode($schema, JSON_THROW_ON_ERROR);
$rebuilt = PortableConfig::fromArray((array) json_decode($json, true, 512, JSON_THROW_ON_ERROR));
echo '   JSON round-trip rebuilds an identical schema: '
    . ($rebuilt->toArray() === $schema ? 'yes' : 'no') . "\n";

// ─────────────────────────────────────────────────────────────────────────
// 3. Compose presets with a user Config, overriding a rule BY NAME.
// ─────────────────────────────────────────────────────────────────────────
echo "\n3. Compose presets with a user override (later layer wins):\n";

// A tenant whose API clients legitimately omit Accept-* headers relaxes the
// suspicious-headers rule by redefining the SAME rule name, so it replaces the
// preset's rule rather than adding a second one.
$tenant = new Config($cache);
$tenant->blocklists->add('preset.scanner.suspicious-headers', static fn($request): bool => false);

$effective = (new Config($cache))->with(
    Presets::scannerBlocking(),
    Presets::sensitivePathBlocking(),
)->with($tenant);

printf("   blocklist rules after composition: %s\n", implode(', ', array_keys($effective->blocklists->rules())));

$firewall = new Firewall($effective);
assertDecision(
    $firewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'nikto/2.5'),
    'blocked',
    'known scanner still blocked by the preset rule',
);
assertDecision(
    $firewall,
    browserRequest('GET', '/.git/config'),
    'blocked',
    'sensitive path still blocked by the preset rule',
);
assertDecision(
    $firewall,
    new ServerRequest('GET', '/api/data'), // no Accept-* headers, no scanner UA
    'pass',
    'header-less client now passes (suspicious-headers rule overridden by name)',
);

// ─────────────────────────────────────────────────────────────────────────
// 4. Versioning (no update mechanism, no network I/O shipped).
// ─────────────────────────────────────────────────────────────────────────
echo "\n4. Preset versioning:\n";
printf("   Presets::VERSION = %s\n", Presets::VERSION);
printf("   shipped presets  = %s\n", implode(', ', Presets::names()));

// Phirewall hardcodes no endpoint and makes no network call. To surface "a
// newer ruleset is available", an integrator compares Presets::VERSION against
// a feed they trust (Packagist, an internal config service, a versioned JSON
// document) with version_compare(). Here the "feed" is a static value, purely
// to show the comparison:
$latestFromYourFeed = '1.2.0';
printf(
    "   current=%s latest=%s -> %s\n",
    Presets::VERSION,
    $latestFromYourFeed,
    version_compare(Presets::VERSION, $latestFromYourFeed, '<') ? 'UPDATE AVAILABLE' : 'up to date',
);

echo "\nAll assertions passed.\n";

/**
 * A request that a normal browser would send (all standard Accept headers).
 */
function browserRequest(string $method, string $path): ServerRequest
{
    return (new ServerRequest($method, $path))
        ->withHeader('User-Agent', 'Mozilla/5.0')
        ->withHeader('Accept', 'text/html')
        ->withHeader('Accept-Language', 'en')
        ->withHeader('Accept-Encoding', 'gzip');
}

/**
 * Assert a firewall decision matches the expected outcome and print the result.
 */
function assertDecision(Firewall $firewall, ServerRequest $serverRequest, string $expected, string $label): void
{
    $actual = $firewall->decide($serverRequest)->outcome->value;

    if ($actual !== $expected) {
        fwrite(STDERR, sprintf("ASSERTION FAILED: %s, expected %s, got %s\n", $label, $expected, $actual));
        exit(1);
    }

    echo sprintf("   [ok] %-58s -> %s\n", $label, strtoupper($actual));
}
