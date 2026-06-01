<?php

declare(strict_types=1);

/**
 * Example 28: PortableConfig signed transport (HMAC-SHA256).
 *
 * PortableConfig::fromArray() / toArray() round-trips a firewall ruleset as a
 * plain array (JSON, a config service, etc.). When that serialized config is
 * read back from storage the application does not fully control — a shared
 * filesystem, an S3 bucket, etcd, a git repo accepting external contributions —
 * an attacker who can write the file can inject an allow-all safelist and turn
 * the whole firewall off. fromArray() validates shape only, not authenticity.
 *
 * toSignedJson() / loadSigned() close that gap: the producer signs the config
 * with a shared secret, the consumer verifies the HMAC-SHA256 signature with a
 * constant-time hash_equals() compare before the rules are ever applied. Any
 * tampering — payload edit, key substitution, or an alg=none downgrade attempt
 * — is rejected.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== PortableConfig Signed Transport Example ===\n\n";

// The signing key is a shared secret between producer and consumer.
// Use at least 16 bytes; 32 random bytes is recommended.
$secretKey = random_bytes(32);

// 1. Producer side: build a ruleset and export it as a signed envelope.
$portableConfig = PortableConfig::create()
    ->setKeyPrefix('signed-app')
    ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
    ->throttle('per-ip', limit: 100, period: 60, key: PortableConfig::keyIp());

$signed = $portableConfig->toSignedJson($secretKey);

echo "1. Produced signed config envelope (header.payload.signature):\n";
echo '   ' . $signed . "\n\n";

// 2. Consumer side: verify + load. A valid signature restores the ruleset.
$restored = PortableConfig::loadSigned($signed, $secretKey);
echo "2. Signature verified — config loaded.\n";
echo '   Round-trip identical: ' . ($restored->toArray() === $portableConfig->toArray() ? 'yes' : 'no') . "\n\n";

// The restored config behaves exactly like the original.
$firewall = new Firewall((new Config(new InMemoryCache()))->combine($restored));
$blocked = $firewall->decide(new ServerRequest('GET', '/admin'));
echo '   /admin is blocked by the restored ruleset: ' . ($blocked->isBlocked() ? 'yes' : 'no') . "\n\n";

// 3. Tampering: attacker swaps in a kill-switch safelist payload but cannot
//    forge the signature without the key. loadSigned() rejects it.
$killSwitch = PortableConfig::create()->safelist('kill', PortableConfig::filterAll());
[$forgedHeader, $forgedPayload] = explode('.', $killSwitch->toSignedJson($secretKey), 3);
[, , $originalSignature] = explode('.', $signed, 3);
$forged = $forgedHeader . '.' . $forgedPayload . '.' . $originalSignature;

echo "3. Attacker injects an allow-all safelist but reuses the old signature:\n";

try {
    PortableConfig::loadSigned($forged, $secretKey);
    echo "   ERROR: tampering was NOT detected!\n\n";
} catch (\RuntimeException $runtimeException) {
    echo '   Rejected: ' . $runtimeException->getMessage() . "\n\n";
}

// 4. Wrong key: a config signed with a different secret is rejected too.
echo "4. Config presented with the wrong verification key:\n";

try {
    PortableConfig::loadSigned($signed, random_bytes(32));
    echo "   ERROR: wrong key was accepted!\n";
} catch (\RuntimeException $runtimeException) {
    echo '   Rejected: ' . $runtimeException->getMessage() . "\n";
}
