<?php

declare(strict_types=1);

/**
 * Example 31: Presets — ready-to-use rule bundles for common scenarios.
 *
 * Presets package the rules you would otherwise hand-write for a recurring use
 * case (API rate limiting, login brute-force protection, scanner blocking,
 * sensitive-path probing). Each preset is defined internally as a PortableConfig
 * — plain, inspectable, serializable data — and exposed as:
 *
 *   Presets::apiRateLimiting()                 -> the underlying PortableConfig
 *
 * Materialize a preset onto a cache with Config::combine(); the result is a
 * live Config that layers with your own rules through Config::compose() /
 * mergedWith() (see example 30). Every rule is namespaced
 * `preset.<area>.*`, so overriding one by name is predictable.
 *
 * This example:
 *   1. uses a preset standalone;
 *   2. inspects/serializes the underlying PortableConfig;
 *   3. composes a preset with a user Config, overriding a rule BY NAME;
 *   4. shows Presets::version() and how an integrator compares it against their
 *      own feed with version_compare() (Phirewall ships no update mechanism and
 *      performs no network I/O — see note).
 *
 * Run: php examples/31-presets.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Preset\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Presets ===\n\n";

$cache = new InMemoryCache();

// ─────────────────────────────────────────────────────────────────────────
// 1. A preset standalone.
// ─────────────────────────────────────────────────────────────────────────
echo "1. Scanner-blocking preset, used as-is:\n";
$scannerFirewall = new Firewall((new Config($cache))->combine(Presets::scannerBlocking()));

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
$portable = Presets::apiRateLimiting();
$schema = $portable->toArray();
foreach ($schema['throttles'] as $throttle) {
    printf(
        "   throttle %-22s limit=%-4d period=%-3ds sliding=%s scope=%s\n",
        $throttle['name'],
        $throttle['limit'],
        $throttle['period'],
        ($throttle['sliding'] ?? false) ? 'yes' : 'no',
        isset($throttle['scope']) ? $throttle['scope']['type'] . ':' . ($throttle['scope']['prefix'] ?? '') : '—',
    );
}

// Round-trips like any PortableConfig (JSON, signed transport, …).
$json = json_encode($schema, JSON_THROW_ON_ERROR);
$rebuilt = PortableConfig::fromArray((array) json_decode($json, true, 512, JSON_THROW_ON_ERROR));
echo "   JSON round-trip rebuilds an identical schema: "
    . ($rebuilt->toArray() === $schema ? 'yes' : 'no') . "\n";

// ─────────────────────────────────────────────────────────────────────────
// 3. Compose a preset with a user Config — overriding a rule BY NAME.
// ─────────────────────────────────────────────────────────────────────────
echo "\n3. Login-protection preset + a user override (later layer wins):\n";

// The preset bans an IP after 5 failures in 15 min. A stricter tenant wants
// 3 failures and a shorter window. They redefine the SAME rule name so it
// replaces the preset's rule rather than adding a second one. Like the preset,
// the override never matches on a request property: a brute-force failure is a
// trusted post-handler signal recorded by the login handler — NOT a forgeable
// marker header (which an attacker could spoof to ban any client's IP).
$strictOverride = new Config($cache);
$strictOverride->fail2ban->add(
    name: Presets::LOGIN_FAILURE_RULE, // same name as the preset rule → replaces it
    threshold: 3,
    period: 600,
    ban: 1800,
    filter: static fn(): bool => false, // never tripped pre-handler; recordFailure() drives it
    key: \Flowd\Phirewall\KeyExtractors::ip(),
);

$effective = (new Config($cache))->combine(Presets::loginProtection())->mergedWith($strictOverride);
printf("   fail2ban rules after composition: %s\n", implode(', ', array_keys($effective->fail2ban->rules())));
echo "   (still ONE 'preset.login.bruteforce' rule — the override replaced it, threshold now 3)\n\n";

// A login handler signals failed authentications through the RequestContext;
// the middleware forwards those signals to fail2ban once the handler returns.
$loginMiddleware = new Middleware($effective, new Psr17Factory());
$failingLoginHandler = new class () implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
        if ($context instanceof RequestContext) {
            // No marker header needed — report the failed auth directly.
            $context->recordFailure(Presets::LOGIN_FAILURE_RULE);
        }

        return new Response(401);
    }
};

$attacker = ['REMOTE_ADDR' => '198.51.100.42'];
for ($attempt = 1; $attempt <= 3; ++$attempt) {
    $status = $loginMiddleware
        ->process(new ServerRequest('POST', '/login', [], null, '1.1', $attacker), $failingLoginHandler)
        ->getStatusCode();
    printf("   failed login attempt %d -> handler returned %d\n", $attempt, $status);
}

// The next request is blocked by the firewall before the handler runs.
$bannedResponse = $loginMiddleware->process(
    new ServerRequest('POST', '/login', [], null, '1.1', $attacker),
    $failingLoginHandler,
);
printf("   subsequent request from the attacker IP -> %d\n", $bannedResponse->getStatusCode());
if ($bannedResponse->getStatusCode() !== 403) {
    fwrite(STDERR, "ASSERTION FAILED: attacker IP should be banned after 3 recorded failures\n");
    exit(1);
}

echo "   [ok] attacker IP banned after 3 recorded failures (overridden threshold)\n";

// A forged marker header from a fresh IP is ignored: bans are never driven by
// any client-controlled request property, so spoofing cannot trigger one.
$loginFirewall = new Firewall($effective);
assertDecision(
    $loginFirewall,
    (new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']))
        ->withHeader('X-Phirewall-Login-Failed', '1'),
    'pass',
    'a forged marker header from a fresh IP is ignored',
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
// document, …) with version_compare(). Here the "feed" is a static value,
// purely to show the comparison:
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
        fwrite(STDERR, sprintf("ASSERTION FAILED: %s — expected %s, got %s\n", $label, $expected, $actual));
        exit(1);
    }

    echo sprintf("   [ok] %-58s -> %s\n", $label, strtoupper($actual));
}
