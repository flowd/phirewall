<?php

declare(strict_types=1);

/**
 * Example 29: PortableConfig as a first-class transport.
 *
 * PortableConfig expresses a firewall ruleset as plain, JSON-serializable data
 * instead of PHP closures. That makes a ruleset portable: you can store it in a
 * database, ship it through a config service, diff it in git, or hand it to
 * another process, then rebuild a live Config from it with Config::combine().
 *
 * This example covers:
 *   1. Building a ruleset with the expanded schema and round-tripping it
 *      through toArray() / fromArray().
 *   2. The signed transport (toSignedJson() / loadSigned()) and how tampering
 *      is rejected.
 *   3. Rules that live in a database and are loaded per request, with a note on
 *      the long-running-worker rebuild-on-change optimization. The DB is
 *      simulated by an in-memory store (no real database needed).
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== PortableConfig: first-class transport ===\n\n";

// ─────────────────────────────────────────────────────────────────────────
// 1. Build a ruleset with the expanded schema, then round-trip it as data.
// ─────────────────────────────────────────────────────────────────────────

$portableConfig = PortableConfig::create()
    ->setKeyPrefix('shop')
    ->enableRateLimitHeaders()
    ->enableResponseHeaders()
    // Safelist health checks so monitoring never gets throttled or banned.
    ->safelist('health', PortableConfig::filterPathEquals('/health'))
    // Block obvious probes by path prefix and by known scanner User-Agents.
    ->blocklist('admin-probe', PortableConfig::filterPathPrefix('/wp-admin'))
    ->blocklist('scanners', PortableConfig::filterKnownScanners())
    // Block a hostile network range (CIDR-aware Ip matcher).
    ->blocklist('bad-net', PortableConfig::filterIp(['203.0.113.0/24']))
    // Sliding-window rate limit per API key (stored as a sha256 fingerprint).
    ->throttle('api', limit: 100, period: 60, key: PortableConfig::keyHashedHeader('X-Api-Key'), sliding: true)
    // Hard volume cap per IP: 1000 requests / minute then a 5-minute ban.
    ->allow2ban('volume-cap', threshold: 1000, period: 60, ban: 300, key: PortableConfig::keyIp())
    // Auto-ban IPs that repeatedly probe a path the app does not serve.
    ->fail2ban('wp-login-probe', threshold: 5, period: 60, ban: 900, filter: PortableConfig::filterPathEquals('/wp-login.php'), key: PortableConfig::keyIp())
    // A pattern blocklist, the kind of catalogue you would keep in a database.
    ->patternBlocklist('threats', [
        PortableConfig::patternEntry(PatternKind::CIDR, '10.66.0.0/16'),
        PortableConfig::patternEntry(PatternKind::PATH_EXACT, '/.env'),
        PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.git(/|$)#'),
        PortableConfig::patternEntry(PatternKind::HEADER_REGEX, '#sqlmap#i', target: 'User-Agent'),
    ]);

$asArray = $portableConfig->toArray();
$asJson = json_encode($asArray, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
echo '1. Ruleset serialized to ' . strlen((string) $asJson) . " bytes of JSON.\n";

$restored = PortableConfig::fromArray(json_decode((string) $asJson, true, 512, JSON_THROW_ON_ERROR));
echo '   toArray() -> JSON -> fromArray() round-trips identically: '
    . ($restored->toArray() === $asArray ? 'yes' : 'no') . "\n\n";

$firewall = new Firewall((new Config(new InMemoryCache()))->combine($restored));

assertDecision($firewall, new ServerRequest('GET', '/health'), 'safelisted', 'health check safelisted');
assertDecision($firewall, new ServerRequest('GET', '/wp-admin/setup-config.php'), 'blocked', 'admin probe blocked');
assertDecision(
    $firewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'),
    'blocked',
    'known scanner blocked',
);
assertDecision(
    $firewall,
    new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.42']),
    'blocked',
    'hostile network blocked',
);
assertDecision(
    $firewall,
    new ServerRequest('GET', '/.env', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.7']),
    'blocked',
    'pattern blocklist hit (/.env)',
);

echo "\n";

// ─────────────────────────────────────────────────────────────────────────
// 2. Signed transport: integrity-protect the config across a trust boundary.
// ─────────────────────────────────────────────────────────────────────────

// Shared secret between the producer and the consumer (>= 16 bytes; 32 random
// bytes recommended). In production this comes from your secrets manager.
$secretKey = random_bytes(32);

$signed = $portableConfig->toSignedJson($secretKey);
echo "2. Produced a signed envelope (header.payload.signature):\n";
echo '   ' . substr($signed, 0, 72) . "...\n";

$verified = PortableConfig::loadSigned($signed, $secretKey);
echo '   Signature verified, ruleset restored: '
    . ($verified->toArray() === $asArray ? 'yes' : 'no') . "\n";

// An attacker who can write to the storage swaps in an allow-all kill switch
// but cannot forge the HMAC without the secret.
$killSwitch = PortableConfig::create()->safelist('kill', PortableConfig::filterAll());
[$forgedHeader, $forgedPayload] = explode('.', $killSwitch->toSignedJson($secretKey), 3);
[, , $originalSignature] = explode('.', $signed, 3);
$forged = $forgedHeader . '.' . $forgedPayload . '.' . $originalSignature;

try {
    PortableConfig::loadSigned($forged, $secretKey);
    echo "   ERROR: tampering was NOT detected!\n\n";
} catch (\RuntimeException $runtimeException) {
    echo '   Tampered kill-switch rejected: ' . $runtimeException->getMessage() . "\n\n";
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Rules in a "database": each request loads the current ruleset.
// ─────────────────────────────────────────────────────────────────────────

echo "3. Rules stored in a database, loaded per request:\n";

// A tiny stand-in for a rules table: a signed blob keyed by version. A real
// implementation would SELECT this from MySQL/Postgres/Redis/etc.
$rulesTable = [
    'version' => 1,
    'blob' => PortableConfig::create()
        ->enableResponseHeaders()
        ->blocklist('bad-bots', PortableConfig::filterKnownScanners())
        ->toSignedJson($secretKey),
];

// Under PHP-FPM the worker process is reused, but userland state does not carry
// over between requests, so every request loads the current blob from the store
// and builds the firewall. Changing the stored rules takes effect on the next
// request, with no deploy and no in-process "reload".
$loadFirewall = static function () use (&$rulesTable, $secretKey): Firewall {
    $portable = PortableConfig::loadSigned($rulesTable['blob'], $secretKey);
    return new Firewall((new Config(new InMemoryCache()))->combine($portable));
};

$liveFirewall = $loadFirewall();
echo "   Request A loaded rules version {$rulesTable['version']} from the store.\n";
assertDecision(
    $liveFirewall,
    (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'nikto/2.5'),
    'blocked',
    'nikto blocked by v1 rules',
);
assertDecision(
    $liveFirewall,
    (new ServerRequest('GET', '/admin'))->withHeader('Accept', '*/*'),
    'pass',
    '/admin still allowed under v1',
);

// An operator publishes a new ruleset: they sign it and bump the version.
$rulesTable['blob'] = PortableConfig::create()
    ->enableResponseHeaders()
    ->blocklist('bad-bots', PortableConfig::filterKnownScanners())
    ->blocklist('lock-admin', PortableConfig::filterPathPrefix('/admin'))
    ->toSignedJson($secretKey);
$rulesTable['version'] = 2;
echo "   Operator published version {$rulesTable['version']}.\n";

// The next request simply loads the store again and sees the new rules.
$liveFirewall = $loadFirewall();
echo "   Request B loaded rules version {$rulesTable['version']} from the store.\n";
assertDecision(
    $liveFirewall,
    (new ServerRequest('GET', '/admin'))->withHeader('Accept', '*/*'),
    'blocked',
    '/admin now blocked under v2',
);

// On a long-running worker (Swoole, RoadRunner, FrankenPHP worker mode, Octane)
// the process persists across requests, so you would keep the built Firewall in
// memory and rebuild it only when $rulesTable['version'] changes.

echo "\nAll assertions passed.\n";

/**
 * Assert a firewall decision matches the expected outcome and print the result.
 */
function assertDecision(Firewall $firewall, ServerRequest $serverRequest, string $expected, string $label): void
{
    $result = $firewall->decide($serverRequest);
    $actual = $result->outcome->value;

    if ($actual !== $expected) {
        fwrite(STDERR, sprintf("ASSERTION FAILED: %s, expected %s, got %s\n", $label, $expected, $actual));
        exit(1);
    }

    echo sprintf("   [ok] %-34s -> %s\n", $label, strtoupper($actual));
}
