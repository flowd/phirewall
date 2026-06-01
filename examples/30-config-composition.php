<?php

declare(strict_types=1);

/**
 * Example 30: Config composition / layering.
 *
 * Real deployments rarely have a single source of firewall rules. Instead they
 * stack layers, each owned by a different party and each overriding the one
 * beneath it:
 *
 *   vendor baseline   (shipped with the product, the same for everyone)
 *     + environment   (staging vs. production differences)
 *       + tenant      (per-customer policy)
 *         + deployment (one specific box / region / maintenance window)
 *
 * Config::compose() (and the fluent $base->mergedWith(...)) merges these into a
 * single effective Config without mutating any input:
 *
 *   - Rules merge BY NAME within each section; the LATER layer wins, replacing
 *     the earlier rule in place and appending genuinely new ones (a union).
 *   - Scalar options (keyPrefix, failOpen, header toggles, …) follow
 *     "last explicit value wins".
 *   - The base layer provides the infrastructure (cache, dispatcher, clock).
 *
 * The first three layers are loaded from PortableConfig (the way you would ship
 * rules as data) and materialized with Config::combine(); the last is a plain
 * hand-built Config.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== Config composition / layering ===\n\n";

$cache = new InMemoryCache();

// ─────────────────────────────────────────────────────────────────────────
// Layer 1 — vendor baseline (shipped as portable data).
// ─────────────────────────────────────────────────────────────────────────
$vendorBaseline = (new Config($cache))->combine(PortableConfig::create()
    ->setKeyPrefix('vendor')
    ->safelist('health', PortableConfig::filterPathEquals('/health'))
    ->blocklist('scanners', PortableConfig::filterKnownScanners()) // curated default list incl. sqlmap, nikto…
    ->blocklist('bad-net', PortableConfig::filterIp(['203.0.113.0/24']))
    ->throttle('api', limit: 100, period: 60, key: PortableConfig::keyHashedHeader('X-Api-Key'), sliding: true)
    ->patternBlocklist('threats', [
        PortableConfig::patternEntry(PatternKind::PATH_EXACT, '/.env'),
        PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.git(/|$)#'),
    ]));

// ─────────────────────────────────────────────────────────────────────────
// Layer 2 — environment overlay (e.g. production): adds rules, turns on headers.
// ─────────────────────────────────────────────────────────────────────────
$environmentOverlay = (new Config($cache))->combine(PortableConfig::create()
    ->enableResponseHeaders()
    ->blocklist('admin-probe', PortableConfig::filterPathPrefix('/wp-admin')));

// ─────────────────────────────────────────────────────────────────────────
// Layer 3 — tenant overlay: OVERRIDES "scanners" by name + adds a volume cap.
// ─────────────────────────────────────────────────────────────────────────
$tenantOverlay = (new Config($cache))->combine(PortableConfig::create()
    ->setKeyPrefix('tenant-acme')
    ->blocklist('scanners', PortableConfig::filterKnownScanners(['evilcorp-bot'])) // replaces the vendor list
    ->allow2ban('volume-cap', threshold: 1_000, period: 60, ban: 300, key: PortableConfig::keyIp()));

// ─────────────────────────────────────────────────────────────────────────
// Layer 4 — per-deployment tweak (a plain Config, not portable): final key
// prefix, fail-closed, and a temporary maintenance block.
// ─────────────────────────────────────────────────────────────────────────
$deploymentTweak = (new Config($cache))
    ->setKeyPrefix('deploy-eu-1')
    ->setFailOpen(false);
$deploymentTweak->blocklists->add('maintenance', static fn($request): bool => str_starts_with((string) $request->getUri()->getPath(), '/legacy'));

// ─────────────────────────────────────────────────────────────────────────
// Compose them. Equivalent: Config::compose($vendorBaseline, $env, $tenant, $deploy).
// ─────────────────────────────────────────────────────────────────────────
$effective = $vendorBaseline->mergedWith($environmentOverlay, $tenantOverlay, $deploymentTweak);

// 1. A rule overridden BY NAME — "scanners" now comes from the tenant layer.
echo "1. Overridden-by-name rule:\n";
echo "   'scanners' is defined in BOTH the vendor baseline and the tenant overlay.\n";
echo "   After composition the tenant version wins (matches 'evilcorp-bot', not the\n";
echo "   vendor default list), proving later layers replace by name rather than duplicate.\n\n";

// 2. A unioned rule set — every layer contributed, deduped by name.
echo "2. Unioned rule sets (deduped by name, base ordering preserved):\n";
printf("   safelists : %s\n", implode(', ', array_keys($effective->safelists->rules())));
printf("   blocklists: %s\n", implode(', ', array_keys($effective->blocklists->rules())));
printf("   throttles : %s\n", implode(', ', array_keys($effective->throttles->rules())));
printf("   allow2ban : %s\n\n", implode(', ', array_keys($effective->allow2ban->rules())));

// 3. Last-wins scalar options.
echo "3. Last-wins options:\n";
printf("   keyPrefix : %s   (vendor -> tenant-acme -> deploy-eu-1; last explicit wins)\n", $effective->getKeyPrefix());
printf("   failOpen  : %s   (only the deployment layer set it, fail-closed)\n", $effective->isFailOpen() ? 'true' : 'false');
printf("   responseHeaders enabled: %s   (set by the environment overlay)\n\n", $effective->responseHeadersEnabled() ? 'yes' : 'no');

// ─────────────────────────────────────────────────────────────────────────
// Prove the composed firewall behaves like the union of every layer.
// ─────────────────────────────────────────────────────────────────────────
echo "4. The composed firewall enforces every layer:\n";
$firewall = new Firewall($effective);

assertDecision($firewall, new ServerRequest('GET', '/health'), 'safelisted', 'vendor safelist (health)');
assertDecision(
    $firewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'evilcorp-bot/2'),
    'blocked',
    'tenant override of "scanners" (evilcorp-bot)',
);
assertDecision(
    $firewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'),
    'pass',
    'vendor default scanner list was replaced (sqlmap now passes)',
);
assertDecision($firewall, new ServerRequest('GET', '/wp-admin/setup-config.php'), 'blocked', 'environment overlay (admin-probe)');
assertDecision(
    $firewall,
    new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.42']),
    'blocked',
    'vendor IP blocklist (bad-net)',
);
assertDecision(
    $firewall,
    new ServerRequest('GET', '/.env', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.7']),
    'blocked',
    'vendor pattern blocklist (threats)',
);
assertDecision($firewall, new ServerRequest('GET', '/legacy/import'), 'blocked', 'deployment maintenance block');

// ─────────────────────────────────────────────────────────────────────────
// Composition never mutates the inputs.
// ─────────────────────────────────────────────────────────────────────────
echo "\n5. Inputs are untouched after composition:\n";
printf("   vendor baseline keyPrefix still '%s' (not 'deploy-eu-1')\n", $vendorBaseline->getKeyPrefix());
printf("   vendor baseline still fail-open: %s\n", $vendorBaseline->isFailOpen() ? 'yes' : 'no');
printf("   vendor 'scanners' still blocks sqlmap on its own: %s\n", (new Firewall($vendorBaseline))
    ->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'))->isBlocked() ? 'yes' : 'no');

echo "\nAll assertions passed.\n";

/**
 * Assert a firewall decision matches the expected outcome and print the result.
 */
function assertDecision(Firewall $firewall, ServerRequest $serverRequest, string $expected, string $label): void
{
    $result = $firewall->decide($serverRequest);
    $actual = $result->outcome->value;

    if ($actual !== $expected) {
        fwrite(STDERR, sprintf("ASSERTION FAILED: %s — expected %s, got %s\n", $label, $expected, $actual));
        exit(1);
    }

    echo sprintf("   [ok] %-48s -> %s\n", $label, strtoupper($actual));
}
