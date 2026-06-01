<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Portable;

use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class PortableConfigTest extends TestCase
{
    public function testBlocklistPathEquals(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableResponseHeaders()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin')); // block /admin

        $config = $portableConfig->toConfig(new InMemoryCache());

        $firewall = new Firewall($config);

        $firewallResult = $firewall->decide(new ServerRequest('GET', '/'));
        $this->assertTrue($firewallResult->isPass());

        $result2 = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $result2->outcome);
        $this->assertSame('blocklist', $result2->headers['X-Phirewall'] ?? '');
        $this->assertSame('admin', $result2->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottleByIpAndRateLimitHeaders(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableRateLimitHeaders()
            ->throttle('ip', 1, 30, PortableConfig::keyIp());

        $config = $portableConfig->toConfig(new InMemoryCache());
        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.5']);
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('1', $firewallResult->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $firewallResult->headers['X-RateLimit-Remaining'] ?? '');

        $throttled = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $throttled->outcome);
        $this->assertSame('1', $throttled->headers['X-RateLimit-Limit'] ?? '');
        $this->assertSame('0', $throttled->headers['X-RateLimit-Remaining'] ?? '');
        $this->assertGreaterThanOrEqual(1, (int)($throttled->headers['X-RateLimit-Reset'] ?? '0'));
    }

    public function testFail2BanWithHeaderFilterAndIpKey(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableResponseHeaders()
            ->fail2ban(
                'login',
                threshold: 2,
                period: 60,
                ban: 300,
                filter: PortableConfig::filterHeaderEquals('X-Login-Failed', '1'),
                key: PortableConfig::keyIp()
            );

        $config = $portableConfig->toConfig(new InMemoryCache());

        $firewall = new Firewall($config);

        $serverRequest = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.20']);
        $fail = $serverRequest->withHeader('X-Login-Failed', '1');
        // threshold=2 (>= semantic): 1st failure passes, 2nd failure triggers the ban.
        $this->assertTrue($firewall->decide($fail)->isPass());
        $second = $firewall->decide($fail);
        $this->assertSame(Outcome::BLOCKED, $second->outcome);
        // Subsequent clean request is still banned
        $firewallResult = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::BLOCKED, $firewallResult->outcome);
        $this->assertSame('fail2ban', $firewallResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('login', $firewallResult->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testSafelistRejectsHeaderEqualsFilter(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/header_equals.*safelist/i');

        PortableConfig::create()->safelist('bypass', PortableConfig::filterHeaderEquals('X-Bypass', 'shh'));
    }

    public function testFromArrayRejectsHeaderEqualsSafelist(): void
    {
        $schema = [
            'safelists' => [
                ['name' => 'bypass', 'filter' => ['type' => 'header_equals', 'name' => 'X-Bypass', 'value' => 'shh']],
            ],
            'blocklists' => [],
            'throttles' => [],
            'fail2bans' => [],
            'tracks' => [],
            'options' => [],
        ];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/header_equals.*safelist/i');

        PortableConfig::fromArray($schema);
    }

    public function testRoundTripExportImport(): void
    {
        $portableConfig = PortableConfig::create()
            ->setKeyPrefix('myapp')
            ->enableRateLimitHeaders()
            ->enableResponseHeaders()
            ->safelist('health', PortableConfig::filterPathEquals('/health'))
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->throttle('ip', 2, 10, PortableConfig::keyIp())
            ->track('login_failed', 60, PortableConfig::filterHeaderEquals('X-Login-Failed', '1'), PortableConfig::keyIp());

        $schema = $portableConfig->toArray();
        $json = json_encode($schema, JSON_THROW_ON_ERROR);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            $this->fail('Decoded data is not an array');
        }

        $portableConfig2 = PortableConfig::fromArray($data);

        $config = $portableConfig2->toConfig(new InMemoryCache());

        $firewall = new Firewall($config);

        // Safelist
        $firewallResult = $firewall->decide(new ServerRequest('GET', '/health'));
        $this->assertTrue($firewallResult->isPass());
        $this->assertSame('health', $firewallResult->headers['X-Phirewall-Safelist'] ?? '');
        // Blocklist
        $blocked = $firewall->decide(new ServerRequest('GET', '/admin'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
        // Throttle
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.77']);
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $tooMany = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::THROTTLED, $tooMany->outcome);
    }

    public function testSignedRoundTripRestoresEquivalentConfig(): void
    {
        $secretKey = random_bytes(32);
        $original = PortableConfig::create()
            ->setKeyPrefix('signed-app')
            ->safelist('health', PortableConfig::filterPathEquals('/health'))
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->throttle('ip', 1, 60, PortableConfig::keyIp());

        $signed = $original->toSignedJson($secretKey);
        $this->assertSame(2, substr_count($signed, '.'), 'Signed envelope must have header.payload.signature');

        $restored = PortableConfig::loadSigned($signed, $secretKey);
        $this->assertSame($original->toArray(), $restored->toArray());
    }

    public function testLoadSignedRejectsTamperedPayload(): void
    {
        $secretKey = random_bytes(32);
        $original = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'));

        $signed = $original->toSignedJson($secretKey);

        // Substitute a kill-switch safelist into the payload while preserving the original signature.
        $tampered = PortableConfig::create()
            ->safelist('kill', PortableConfig::filterAll());
        $tamperedSigned = $tampered->toSignedJson($secretKey);
        [$tamperedHeader, $tamperedPayload, ] = explode('.', $tamperedSigned, 3);
        [, , $originalSignature] = explode('.', $signed, 3);
        $forged = $tamperedHeader . '.' . $tamperedPayload . '.' . $originalSignature;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/signature verification failed/i');
        PortableConfig::loadSigned($forged, $secretKey);
    }

    public function testLoadSignedRejectsWrongKey(): void
    {
        $producerKey = random_bytes(32);
        $consumerKey = random_bytes(32);
        $signed = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->toSignedJson($producerKey);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/signature verification failed/i');
        PortableConfig::loadSigned($signed, $consumerKey);
    }

    public function testLoadSignedRejectsAlgorithmDowngrade(): void
    {
        $secretKey = random_bytes(32);
        $signed = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->toSignedJson($secretKey);

        [$header, $payload, $signature] = explode('.', $signed, 3);

        // Forge an alg=none header — common JWT-style attack. Reuse the real
        // token's header (keeping its typ) and flip only alg, so the test is not
        // coupled to the hard-coded wire-format version string.
        $rawHeader = strtr($header, '-_', '+/');
        $rawHeader .= str_repeat('=', (4 - strlen($rawHeader) % 4) % 4);
        /** @var array<string, mixed> $decodedHeader */
        $decodedHeader = (array) json_decode((string) base64_decode($rawHeader, true), true);
        $decodedHeader['alg'] = 'none';
        $forgedHeader = rtrim(strtr(base64_encode((string) json_encode($decodedHeader)), '+/', '-_'), '=');
        $forged = $forgedHeader . '.' . $payload . '.' . $signature;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/unsupported or malformed/i');
        PortableConfig::loadSigned($forged, $secretKey);
    }

    public function testToSignedJsonRejectsShortSecretKey(): void
    {
        $portableConfig = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/at least 16 bytes/i');
        $portableConfig->toSignedJson('too-short');
    }

    public function testLoadSignedRejectsMalformedEnvelope(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/three "."-separated segments/');
        PortableConfig::loadSigned('not.a.valid.jws', random_bytes(32));
    }

    public function testLoadSignedRejectsStructurallyInvalidPayload(): void
    {
        $secretKey = random_bytes(32);
        $b64 = static fn(string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

        // A validly-signed but structurally malformed payload (a scalar where a
        // section array is expected) must surface as InvalidArgumentException,
        // not a TypeError that escapes loadSigned()'s documented contract.
        $header = $b64((string) json_encode(['alg' => 'HS256', 'typ' => 'phirewall.config.v1']));
        $payload = $b64((string) json_encode(['blocklists' => 'not-an-array']));
        $signature = $b64(hash_hmac('sha256', $header . '.' . $payload, $secretKey, true));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/structurally invalid/');
        PortableConfig::loadSigned($header . '.' . $payload . '.' . $signature, $secretKey);
    }

    public function testLoadSignedRejectsTamperingAtBothEndsOfTheSignature(): void
    {
        // A naive byte-by-byte compare can short-circuit on the first differing
        // byte; hash_equals() compares the full length regardless of position.
        // Tampering with either the first or the last signature byte must be
        // rejected identically.
        $secretKey = random_bytes(32);
        $signed = PortableConfig::create()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin'))
            ->toSignedJson($secretKey);

        [$header, $payload, $encodedSignature] = explode('.', $signed, 3);
        $rawSignature = (string) base64_decode(strtr($encodedSignature, '-_', '+/'), true);

        foreach ([0, strlen($rawSignature) - 1] as $byteIndex) {
            $flippedByte = $rawSignature[$byteIndex] ^ "\xff";
            $mutated = substr_replace($rawSignature, $flippedByte, $byteIndex, 1);
            $forged = $header . '.' . $payload . '.' . rtrim(strtr(base64_encode($mutated), '+/', '-_'), '=');

            try {
                PortableConfig::loadSigned($forged, $secretKey);
                $this->fail(sprintf('Tampering with signature byte %d was not rejected.', $byteIndex));
            } catch (\RuntimeException $runtimeException) {
                $this->assertMatchesRegularExpression('/signature verification failed/i', $runtimeException->getMessage());
            }
        }
    }

    public function testSignatureComparisonUsesConstantTimeHashEquals(): void
    {
        // Guard against a future "simplification" of the verification to a raw
        // ===/!== comparison, which would leak timing information about how many
        // leading signature bytes matched.
        $reflectionMethod = new \ReflectionMethod(PortableConfig::class, 'loadSigned');
        $source = file($reflectionMethod->getFileName() ?: '');
        $this->assertIsArray($source);

        $body = implode('', array_slice(
            $source,
            $reflectionMethod->getStartLine() - 1,
            $reflectionMethod->getEndLine() - $reflectionMethod->getStartLine() + 1,
        ));

        $this->assertStringContainsString('hash_equals(', $body, 'loadSigned() must verify the signature with hash_equals().');
        $this->assertDoesNotMatchRegularExpression(
            '/\$\w*signature\w*\s*(?:===|!==)\s*\$|\$\w+\s*(?:===|!==)\s*\$\w*signature/i',
            $body,
            'loadSigned() must not compare signatures with === / !== (timing side channel); use hash_equals().',
        );
    }
}
