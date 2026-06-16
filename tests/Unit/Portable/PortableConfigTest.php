<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Portable;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class PortableConfigTest extends TestCase
{
    public function testBlocklistPathEquals(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableResponseHeaders()
            ->blocklist('admin', PortableConfig::filterPathEquals('/admin')); // block /admin

        $config = (new Config(new InMemoryCache()))->with($portableConfig);

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

        $config = (new Config(new InMemoryCache()))->with($portableConfig);
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

    public function testThrottleScopeOnlyCountsMatchingRequests(): void
    {
        $portableConfig = PortableConfig::create()
            ->throttle(
                'api',
                limit: 1,
                period: 30,
                key: PortableConfig::keyIp(),
                scope: PortableConfig::filterPathPrefix('/api'),
            );

        $config = (new Config(new InMemoryCache()))->with($portableConfig);
        $firewall = new Firewall($config);

        $apiRequest = new ServerRequest('GET', '/api/users', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9']);
        $this->assertTrue($firewall->decide($apiRequest)->isPass());
        // Second request on the scoped path exceeds the limit of 1.
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($apiRequest)->outcome);

        // Requests outside the scope are never counted, no matter how many.
        $otherRequest = new ServerRequest('GET', '/public', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9']);
        for ($i = 0; $i < 5; ++$i) {
            $this->assertTrue($firewall->decide($otherRequest)->isPass());
        }
    }

    public function testIpScopedThrottleLateBindsToConfigResolver(): void
    {
        $portableConfig = PortableConfig::create()
            ->throttle(
                'ip-scoped',
                limit: 1,
                period: 60,
                key: PortableConfig::keyIp(),
                scope: PortableConfig::filterIp(['203.0.113.7']),
            );

        // Materialize first, then set the resolver: late-binding means the scope
        // honours it regardless of ordering (a materialization-time capture would not).
        $config = (new Config(new InMemoryCache()))->with($portableConfig);
        $config->setIpResolver(static function (ServerRequestInterface $serverRequest): ?string {
            $value = $serverRequest->getHeaderLine('X-Real-IP');
            return $value === '' ? null : $value;
        });
        $firewall = new Firewall($config);

        // In-scope client identified via X-Real-IP (REMOTE_ADDR is the proxy): the
        // scope matches through the Config's resolver, so the throttle counts it.
        $inScope = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '203.0.113.7');
        $this->assertTrue($firewall->decide($inScope)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($inScope)->outcome);

        // A client outside the scope (different forwarded IP) is never throttled.
        $outOfScope = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))->withHeader('X-Real-IP', '198.51.100.9');
        for ($i = 0; $i < 3; ++$i) {
            $this->assertTrue($firewall->decide($outOfScope)->isPass());
        }
    }

    public function testThrottleScopeSurvivesRoundTrip(): void
    {
        $portableConfig = PortableConfig::create()
            ->throttle(
                'api',
                limit: 1,
                period: 30,
                key: PortableConfig::keyIp(),
                sliding: true,
                scope: PortableConfig::filterPathPrefix('/api'),
            );

        $schema = $portableConfig->toArray();
        $this->assertSame(['type' => 'path_prefix', 'prefix' => '/api'], $schema['throttles'][0]['scope'] ?? null);

        $json = json_encode($schema, JSON_THROW_ON_ERROR);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($data);

        $firewall = new Firewall((new Config(new InMemoryCache()))->with(PortableConfig::fromArray($data)));
        $apiRequest = new ServerRequest('GET', '/api/items', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.7']);
        $this->assertTrue($firewall->decide($apiRequest)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($apiRequest)->outcome);
    }

    public function testThrottleScopeRejectsInvalidFilter(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PortableConfig::create()->throttle(
            'api',
            limit: 1,
            period: 30,
            key: PortableConfig::keyIp(),
            scope: ['type' => 'not-a-real-filter'],
        );
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

        $config = (new Config(new InMemoryCache()))->with($portableConfig);

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
            'allow2bans' => [],
            'tracks' => [],
            'patternBackends' => [],
            'patternBlocklists' => [],
            'options' => [],
        ];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/header_equals.*safelist/i');

        PortableConfig::fromArray($schema);
    }

    public function testSafelistRejectsHeaderPresentFilter(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/not allowed for safelists/i');

        PortableConfig::create()->safelist('bypass', PortableConfig::filterHeaderPresent('X-Bypass'));
    }

    public function testSafelistRejectsHeaderRegexFilter(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/not allowed for safelists/i');

        PortableConfig::create()->safelist('bypass', PortableConfig::filterHeaderRegex('X-Bypass', '/^ok$/'));
    }

    public function testFromArrayRejectsHeaderPresentSafelist(): void
    {
        $schema = [
            'safelists' => [
                ['name' => 'bypass', 'filter' => ['type' => 'header_present', 'name' => 'X-Bypass']],
            ],
            'blocklists' => [],
            'throttles' => [],
            'fail2bans' => [],
            'allow2bans' => [],
            'tracks' => [],
            'patternBackends' => [],
            'patternBlocklists' => [],
            'options' => [],
        ];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/not allowed for safelists/i');

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

        $config = (new Config(new InMemoryCache()))->with($portableConfig2);

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
        // section expects objects) must surface as a transport-level
        // InvalidArgumentException, not a raw TypeError from offset access. The
        // per-section structural guards reject it precisely at the boundary.
        $header = $b64((string) json_encode(['alg' => 'HS256', 'typ' => 'phirewall.config.v1']));
        $payload = $b64((string) json_encode(['blocklists' => ['not-an-object']]));
        $signature = $b64(hash_hmac('sha256', $header . '.' . $payload, $secretKey, true));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid blocklist entry/');
        PortableConfig::loadSigned($header . '.' . $payload . '.' . $signature, $secretKey);
    }

    public function testLoadSignedRejectsJsonArrayPayload(): void
    {
        $secretKey = random_bytes(32);
        $b64 = static fn(string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

        // A correctly-signed envelope whose payload decodes to a non-empty JSON
        // list must be rejected: a config payload is a keyed object, never a
        // sequential array. (An empty object/array is a valid no-op config.)
        $header = $b64((string) json_encode(['alg' => 'HS256', 'typ' => 'phirewall.config.v1']));
        $payload = $b64((string) json_encode([1, 2, 3]));
        $signature = $b64(hash_hmac('sha256', $header . '.' . $payload, $secretKey, true));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/JSON object/');
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

    public function testAllow2BanRoundTripBansAfterThreshold(): void
    {
        $portableConfig = $this->roundTrip(
            PortableConfig::create()
                ->enableResponseHeaders()
                ->allow2ban('volume-cap', threshold: 2, period: 60, ban: 300, key: PortableConfig::keyIp())
        );

        $firewall = new Firewall((new Config(new InMemoryCache()))->with($portableConfig));
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9']);

        // threshold=2 (>= semantics): 1st request passes, 2nd reaches the cap and is banned.
        $this->assertTrue($firewall->decide($serverRequest)->isPass());
        $banned = $firewall->decide($serverRequest);
        $this->assertSame(Outcome::BLOCKED, $banned->outcome);
        $this->assertSame('allow2ban', $banned->headers['X-Phirewall'] ?? '');
        $this->assertSame('volume-cap', $banned->headers['X-Phirewall-Matched'] ?? '');
    }

    public function testThrottleSlidingFlagRoundTrips(): void
    {
        $portableConfig = PortableConfig::create()
            ->throttle('sliding-ip', 5, 60, PortableConfig::keyIp(), sliding: true)
            ->throttle('fixed-ip', 5, 60, PortableConfig::keyIp());

        $schema = $portableConfig->toArray();
        $this->assertTrue($schema['throttles'][0]['sliding'] ?? false);
        $this->assertArrayNotHasKey('sliding', $schema['throttles'][1]);

        $config = (new Config(new InMemoryCache()))->with($this->roundTrip($portableConfig));
        $rules = $config->throttles->rules();
        $this->assertTrue($rules['sliding-ip']->isSliding());
        $this->assertFalse($rules['fixed-ip']->isSliding());
    }

    public function testPathPrefixFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('admin', PortableConfig::filterPathPrefix('/admin'))
        );

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('GET', '/admin/users'))->outcome);
    }

    public function testPathRegexFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('php-files', PortableConfig::filterPathRegex('#\.php$#'))
        );

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/index.html'))->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('GET', '/shell.php'))->outcome);
    }

    public function testNoneFilterNeverMatches(): void
    {
        $portable = PortableConfig::create()->blocklist('never', PortableConfig::filterNone());
        $firewall = $this->firewallFrom($portable);

        // A never-match filter blocks nothing, regardless of the request.
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertTrue($firewall->decide(new ServerRequest('POST', '/admin', ['X-Anything' => 'yes']))->isPass());

        // It is a first-class portable filter and survives a round trip.
        $this->assertSame(
            [['name' => 'never', 'filter' => ['type' => 'none']]],
            PortableConfig::fromArray($portable->toArray())->toArray()['blocklists'],
        );
    }

    public function testMethodInFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('writes', PortableConfig::filterMethodIn(['post', 'put']))
        );

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('POST', '/'))->outcome);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('PUT', '/'))->outcome);
    }

    public function testHeaderPresentFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('has-debug', PortableConfig::filterHeaderPresent('X-Debug'))
        );

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $blocked = $firewall->decide((new ServerRequest('GET', '/'))->withHeader('X-Debug', '1'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
    }

    public function testHeaderRegexFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('bot-ua', PortableConfig::filterHeaderRegex('User-Agent', '#bot#i'))
        );

        $this->assertTrue($firewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'Mozilla/5.0'))->isPass());
        $blocked = $firewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'EvilBot/2.0'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);
    }

    public function testIpFilterBlocksCidrRange(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('bad-net', PortableConfig::filterIp(['192.0.2.0/24', '203.0.113.7']))
        );

        $inRange = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.55']);
        $exact = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.7']);
        $outside = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.1']);

        $this->assertSame(Outcome::BLOCKED, $firewall->decide($inRange)->outcome);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($exact)->outcome);
        $this->assertTrue($firewall->decide($outside)->isPass());
    }

    public function testKnownScannersFilterBlocksDefaultsAndCustom(): void
    {
        $defaultsFirewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('scanners', PortableConfig::filterKnownScanners())
        );
        $blocked = $defaultsFirewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'));
        $this->assertSame(Outcome::BLOCKED, $blocked->outcome);

        $customFirewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('scanners', PortableConfig::filterKnownScanners(['acme-crawler']))
        );
        $this->assertTrue($customFirewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7'))->isPass());
        $customBlocked = $customFirewall->decide((new ServerRequest('GET', '/'))->withHeader('User-Agent', 'acme-crawler/9'));
        $this->assertSame(Outcome::BLOCKED, $customBlocked->outcome);
    }

    public function testSuspiciousHeadersFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('suspicious', PortableConfig::filterSuspiciousHeaders())
        );

        // Missing the default browser headers -> blocked.
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('GET', '/'))->outcome);

        $browserLike = (new ServerRequest('GET', '/'))
            ->withHeader('Accept', '*/*')
            ->withHeader('Accept-Language', 'en')
            ->withHeader('Accept-Encoding', 'gzip');
        $this->assertTrue($firewall->decide($browserLike)->isPass());
    }

    public function testHashedHeaderKeyThrottles(): void
    {
        $portableConfig = $this->roundTrip(
            PortableConfig::create()->throttle('per-api-key', 1, 60, PortableConfig::keyHashedHeader('X-Api-Key'))
        );
        $firewall = new Firewall((new Config(new InMemoryCache()))->with($portableConfig));

        $request = (new ServerRequest('GET', '/'))->withHeader('X-Api-Key', 'secret-token');
        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($request)->outcome);
    }

    public function testPatternBlocklistRoundTripBlocksCidrAndPath(): void
    {
        $portableConfig = PortableConfig::create()
            ->enableResponseHeaders()
            ->patternBlocklist('threats', [
                PortableConfig::patternEntry(PatternKind::CIDR, '10.0.0.0/8'),
                PortableConfig::patternEntry(PatternKind::PATH_EXACT, '/wp-login.php'),
                PortableConfig::patternEntry(PatternKind::HEADER_REGEX, '#curl#i', target: 'User-Agent'),
            ]);

        $firewall = $this->firewallFrom($portableConfig);

        $cidrHit = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.1.2.3']);
        $cidrResult = $firewall->decide($cidrHit);
        $this->assertSame(Outcome::BLOCKED, $cidrResult->outcome);
        $this->assertSame('blocklist', $cidrResult->headers['X-Phirewall'] ?? '');
        $this->assertSame('threats', $cidrResult->headers['X-Phirewall-Matched'] ?? '');

        $pathHit = new ServerRequest('GET', '/wp-login.php', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.4']);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($pathHit)->outcome);

        $headerHit = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.4']))
            ->withHeader('User-Agent', 'curl/8.1');
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($headerHit)->outcome);

        $clean = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.4']);
        $this->assertTrue($firewall->decide($clean)->isPass());
    }

    public function testPatternBackendSharedAcrossBlocklists(): void
    {
        $portableConfig = $this->roundTrip(
            PortableConfig::create()
                ->addPatternBackend('shared', [PortableConfig::patternEntry(PatternKind::IP, '192.0.2.10')])
                ->blocklistFromBackend('block-a', 'shared')
                ->blocklistFromBackend('block-b', 'shared')
        );

        $config = (new Config(new InMemoryCache()))->with($portableConfig);
        $this->assertArrayHasKey('block-a', $config->blocklists->rules());
        $this->assertArrayHasKey('block-b', $config->blocklists->rules());

        $firewall = new Firewall($config);
        $hit = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.10']);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($hit)->outcome);
    }

    public function testOptionsFailOpenAndOwaspDiagnosticsRoundTrip(): void
    {
        $portableConfig = $this->roundTrip(
            PortableConfig::create()
                ->setFailOpen(false)
                ->enableOwaspDiagnosticsHeader()
        );

        $schema = $portableConfig->toArray();
        $this->assertFalse($schema['options']['failOpen'] ?? true);
        $this->assertTrue($schema['options']['owaspDiagnosticsHeader'] ?? false);

        $config = (new Config(new InMemoryCache()))->with($portableConfig);
        $this->assertFalse($config->isFailOpen());
        $this->assertTrue($config->owaspDiagnosticsHeaderEnabled());
    }

    public function testSignedRoundTripWithExpandedSchemaIsIdentical(): void
    {
        $secretKey = random_bytes(32);
        $original = PortableConfig::create()
            ->setKeyPrefix('expanded')
            ->setFailOpen(false)
            ->blocklist('writes', PortableConfig::filterMethodIn(['POST', 'DELETE']))
            ->blocklist('scanners', PortableConfig::filterKnownScanners())
            ->blocklist('bad-net', PortableConfig::filterIp(['10.0.0.0/8']))
            ->allow2ban('cap', threshold: 100, period: 60, ban: 600, key: PortableConfig::keyIp())
            ->throttle('api', 10, 60, PortableConfig::keyHashedHeader('X-Api-Key'), sliding: true)
            ->patternBlocklist('threats', [PortableConfig::patternEntry(PatternKind::PATH_REGEX, '#/\.git#')]);

        $restored = PortableConfig::loadSigned($original->toSignedJson($secretKey), $secretKey);
        $this->assertSame($original->toArray(), $restored->toArray());
    }

    public function testFromArrayRejectsUnknownFilterType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid filter type/');
        PortableConfig::fromArray(['blocklists' => [['name' => 'x', 'filter' => ['type' => 'nope']]]]);
    }

    public function testFromArrayRejectsInvalidRegexPattern(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/valid PCRE pattern/');
        PortableConfig::fromArray(['blocklists' => [['name' => 'x', 'filter' => ['type' => 'path_regex', 'pattern' => '#(unterminated']]]]);
    }

    public function testFromArrayRejectsInvalidPatternEntryKind(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid pattern entry kind/');
        PortableConfig::fromArray([
            'patternBackends' => [['name' => 'b', 'entries' => [['kind' => 'bogus', 'value' => 'x']]]],
        ]);
    }

    public function testFromArrayRejectsHeaderPatternEntryWithoutTarget(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/requires a non-empty target/');
        PortableConfig::fromArray([
            'patternBackends' => [['name' => 'b', 'entries' => [['kind' => 'header_exact', 'value' => 'x']]]],
        ]);
    }

    public function testFromArrayRejectsNonBooleanFailOpen(): void
    {
        // A JSON-decoded "failOpen": "false" arrives as a string; it must be
        // rejected at the transport boundary rather than crashing later during
        // Config::with()'s strictly-typed Config::setFailOpen(bool) call.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/failOpen.*boolean/');
        PortableConfig::fromArray(['options' => ['failOpen' => 'false']]);
    }

    public function testFromArrayAcceptsBooleanFailOpen(): void
    {
        $portableConfig = PortableConfig::fromArray(['options' => ['failOpen' => false]]);

        $config = (new Config(new InMemoryCache()))->with($portableConfig);

        $this->assertFalse($config->isFailOpen());
    }

    public function testFromArrayRejectsNullThrottleScope(): void
    {
        // A present-but-null throttle "scope" is rejected at the boundary
        // (mirroring the failOpen guard): when the key is present it must be an
        // array filter, so a malformed config-generation path is caught early
        // rather than silently dropped to "no scope".
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid throttle scope/');
        PortableConfig::fromArray([
            'throttles' => [['name' => 't', 'limit' => 1, 'period' => 60, 'key' => ['type' => 'ip'], 'scope' => null]],
        ]);
    }

    public function testFilterMethodInRejectsEmptyList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/filterMethodIn.*non-empty/');
        PortableConfig::filterMethodIn([]);
    }

    public function testFilterIpRejectsEmptyList(): void
    {
        // An empty IP list silently compiles into a matcher that matches
        // nothing; the builder must reject it rather than emit a no-op rule.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/filterIp.*non-empty/');
        PortableConfig::filterIp([]);
    }

    public function testFilterKnownScannersRejectsEmptyList(): void
    {
        // Empty list would serialize as patterns: [] which fromArray() rejects;
        // pass null (the default) to use the curated pattern set instead.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/filterKnownScanners.*non-empty/');
        PortableConfig::filterKnownScanners([]);
    }

    public function testFilterSuspiciousHeadersEmptyListDisablesTheFilter(): void
    {
        // An explicit empty list expresses "require no headers" (the matcher
        // never matches), distinct from null which selects the curated defaults.
        // Unlike the sibling builders that have no disable semantics, it must be
        // accepted and round-trip through the transport rather than throw.
        $this->assertSame(
            ['type' => 'suspicious_headers', 'headers' => []],
            PortableConfig::filterSuspiciousHeaders([]),
        );

        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('suspicious', PortableConfig::filterSuspiciousHeaders([]))
        );

        // A request missing every default header still passes: the filter is disabled.
        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
    }

    public function testFilterIpRejectsBlankEntry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/non-empty string/');
        PortableConfig::filterIp(['203.0.113.7', '   ']);
    }

    public function testFromArrayRejectsNonArrayBlocklistEntry(): void
    {
        // Sibling section (unchanged by the diff) must reject malformed entries
        // with the same transport error, not a raw TypeError from $b['filter'].
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid blocklist entry/');
        PortableConfig::fromArray(['blocklists' => ['not-an-object']]);
    }

    public function testFromArrayRejectsNonArrayAllow2banEntry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid allow2ban entry/');
        PortableConfig::fromArray(['allow2bans' => [42]]);
    }

    public function testFromArrayRejectsNonArrayPatternBackendEntry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid pattern backend entry/');
        PortableConfig::fromArray(['patternBackends' => ['scalar']]);
    }

    public function testFromArrayRejectsNonArrayPatternBlocklistEntry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid pattern blocklist entry/');
        PortableConfig::fromArray(['patternBlocklists' => ['scalar']]);
    }

    public function testFilterMethodInRequiresList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/method_in requires/');
        PortableConfig::fromArray(['blocklists' => [['name' => 'x', 'filter' => ['type' => 'method_in', 'methods' => 'POST']]]]);
    }

    public function testFromArrayRejectsUnknownKeyType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid key extractor type/');
        PortableConfig::fromArray(['throttles' => [['name' => 'x', 'limit' => 1, 'period' => 1, 'key' => ['type' => 'nope']]]]);
    }

    public function testToConfigBuildsEveryFilterAndKeyVariant(): void
    {
        $portableConfig = PortableConfig::create()
            ->safelist('all', PortableConfig::filterAll())
            ->safelist('prefix', PortableConfig::filterPathPrefix('/p'))
            ->blocklist('eq', PortableConfig::filterPathEquals('/x'))
            ->blocklist('rx', PortableConfig::filterPathRegex('#^/y#'))
            ->blocklist('meq', PortableConfig::filterMethodEquals('POST'))
            ->blocklist('min', PortableConfig::filterMethodIn(['PUT']))
            ->blocklist('heq', PortableConfig::filterHeaderEquals('X-A', '1'))
            ->blocklist('hpr', PortableConfig::filterHeaderPresent('X-B'))
            ->blocklist('hrx', PortableConfig::filterHeaderRegex('X-C', '#z#'))
            ->blocklist('ip', PortableConfig::filterIp(['1.2.3.4']))
            ->blocklist('ks', PortableConfig::filterKnownScanners())
            ->blocklist('sh', PortableConfig::filterSuspiciousHeaders(['Accept']))
            ->throttle('t-ip', 1, 60, PortableConfig::keyIp())
            ->throttle('t-method', 1, 60, PortableConfig::keyMethod())
            ->throttle('t-path', 1, 60, PortableConfig::keyPath())
            ->throttle('t-header', 1, 60, PortableConfig::keyHeader('X-H'))
            ->throttle('t-hh', 1, 60, PortableConfig::keyHashedHeader('X-K'))
            ->fail2ban('f', threshold: 2, period: 60, ban: 300, filter: PortableConfig::filterHeaderEquals('X-F', '1'), key: PortableConfig::keyIp())
            ->allow2ban('a', threshold: 2, period: 60, ban: 300, key: PortableConfig::keyMethod())
            ->track('tr', 60, PortableConfig::filterPathPrefix('/api'), PortableConfig::keyPath(), 5);

        $config = (new Config(new InMemoryCache()))->with($this->roundTrip($portableConfig));

        $this->assertCount(2, $config->safelists->rules());
        $this->assertCount(10, $config->blocklists->rules());
        $this->assertCount(5, $config->throttles->rules());
        $this->assertCount(1, $config->fail2ban->rules());
        $this->assertCount(1, $config->allow2ban->rules());
        $this->assertCount(1, $config->tracks->rules());
    }

    public function testMethodEqualsFilterBlocks(): void
    {
        $firewall = $this->firewallFrom(
            PortableConfig::create()->blocklist('post-only', PortableConfig::filterMethodEquals('post'))
        );

        $this->assertTrue($firewall->decide(new ServerRequest('GET', '/'))->isPass());
        $this->assertSame(Outcome::BLOCKED, $firewall->decide(new ServerRequest('POST', '/'))->outcome);
    }

    public function testPatternEntryWithMetadataAndExpiryRoundTrips(): void
    {
        $entry = PortableConfig::patternEntry(
            PatternKind::IP,
            '192.0.2.99',
            expiresAt: 4_102_444_800, // far future -> still active
            addedAt: 1_700_000_000,
            metadata: ['source' => 'threat-feed', 'severity' => 5],
        );
        $this->assertSame('threat-feed', $entry['metadata']['source'] ?? null);

        $portableConfig = $this->roundTrip(
            PortableConfig::create()->enableResponseHeaders()->patternBlocklist('feed', [$entry])
        );

        $firewall = new Firewall((new Config(new InMemoryCache()))->with($portableConfig));
        $hit = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.99']);
        $this->assertSame(Outcome::BLOCKED, $firewall->decide($hit)->outcome);
    }

    public function testTrackBuilderRejectsZeroLimit(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/limit must be at least 1/');
        PortableConfig::create()->track('t', 60, PortableConfig::filterAll(), PortableConfig::keyIp(), 0);
    }

    public function testPatternBackendBuilderRejectsEmptyNames(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must not be empty/');
        PortableConfig::create()->addPatternBackend('', [PortableConfig::patternEntry(PatternKind::IP, '1.2.3.4')]);
    }

    public function testBlocklistFromBackendRejectsEmptyBackendName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must not be empty/');
        PortableConfig::create()->blocklistFromBackend('rule', '');
    }

    public function testFromArrayRejectsDanglingPatternBackendReference(): void
    {
        // A pattern blocklist referencing a backend that is not registered must
        // fail at load time, not later during Config::with().
        $schema = [
            'safelists' => [],
            'blocklists' => [],
            'throttles' => [],
            'fail2bans' => [],
            'allow2bans' => [],
            'tracks' => [],
            'patternBackends' => [],
            'patternBlocklists' => [
                ['name' => 'threats', 'backend' => 'missing-backend'],
            ],
            'options' => [],
        ];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/unknown pattern backend/i');

        PortableConfig::fromArray($schema);
    }

    /**
     * Export -> JSON -> decode -> import, mirroring how a portable config crosses a process boundary.
     */
    private function roundTrip(PortableConfig $portableConfig): PortableConfig
    {
        $json = json_encode($portableConfig->toArray(), JSON_THROW_ON_ERROR);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($data);

        $imported = PortableConfig::fromArray($data);
        $this->assertSame($portableConfig->toArray(), $imported->toArray());

        return $imported;
    }

    private function firewallFrom(PortableConfig $portableConfig): Firewall
    {
        return new Firewall((new Config(new InMemoryCache()))->with($this->roundTrip($portableConfig)));
    }
}
