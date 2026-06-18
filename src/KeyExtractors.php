<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Closure;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Common key extractor helpers for counter rules (throttle / fail2ban / allow2ban / track).
 *
 * The client IP is the default discriminator: omit a rule's key (or use
 * PortableConfig::keyIp()) and the firewall resolves it through the Config's IP resolver,
 * falling back to REMOTE_ADDR when none is set. Configure proxy trust once with
 * $config->setIpResolver((new TrustedProxyResolver([...]))->resolve(...)). Reach for
 * {@see ip()} only when you deliberately want the raw REMOTE_ADDR peer address.
 */
final class KeyExtractors
{
    /**
     * The raw REMOTE_ADDR peer address.
     *
     * @deprecated The name is ambiguous and it bypasses the Config IP resolver. To key on
     *   the client IP, omit the rule's key (or use PortableConfig::keyIp()) so it resolves
     *   through the Config's IP resolver (else REMOTE_ADDR). For the raw connecting peer,
     *   read $request->getServerParams()['REMOTE_ADDR'] directly.
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function ip(): Closure
    {
        return static function (ServerRequestInterface $serverRequest): ?string {
            $ip = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;

            return is_string($ip) && $ip !== '' ? $ip : null;
        };
    }

    /**
     * Extract normalized HTTP method (uppercase).
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function method(): Closure
    {
        return static function (ServerRequestInterface $serverRequest): ?string {
            $method = $serverRequest->getMethod();
            return $method === '' ? null : strtoupper($method);
        };
    }

    /**
     * Extract request path (pathname only).
     * @return Closure(ServerRequestInterface): string
     */
    public static function path(): Closure
    {
        return static function (ServerRequestInterface $serverRequest): string {
            $path = $serverRequest->getUri()->getPath();
            return $path === '' ? '/' : $path;
        };
    }

    /**
     * Extract a header value by name via PSR-7 getHeaderLine(), so repeated header lines are
     * joined with commas (not just the first value). Returns null when the header is absent or
     * present but empty.
     *
     * A null key skips the rule entirely: a throttle / fail2ban / allow2ban rule keyed on a
     * header does NOT apply to a request that omits the header, so an unauthenticated client can
     * sidestep the limit by simply not sending it. Pair a header-keyed limiter with a blocklist
     * or suspicious-header rule that rejects requests missing the header, or key on the client IP.
     *
     * The raw value flows into per-key counters and into the ban registry for
     * rules using it. When the header carries a credential or other value the
     * integrator does not want stored verbatim in the cache backend (e.g.
     * `Authorization`, `Cookie`, `X-Api-Key`), use {@see hashedHeader()} so
     * only a sha256 fingerprint reaches the storage layer.
     *
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function header(string $name): Closure
    {
        return static function (ServerRequestInterface $serverRequest) use ($name): ?string {
            $value = $serverRequest->getHeaderLine($name);
            return $value === '' ? null : $value;
        };
    }

    /**
     * Extract a header value by name and return its sha256 fingerprint.
     *
     * Preferred over {@see header()} when the header value is sensitive
     * (`Authorization`, `Cookie`, `X-Api-Key`, …). Per-key counters and ban
     * registry entries then carry the fingerprint rather than the original
     * value, so a passive read of the cache backend does not surface the
     * raw header.
     *
     * The hash is unkeyed sha256 — a deterministic identifier suitable as a
     * bucket key, not a credential-hardening primitive. A low-entropy header
     * value (short PIN, predictable cookie) remains grindable from a leaked
     * cache dump, and the fingerprint does not defeat a chosen-key probing
     * attacker who can send guesses and observe ban behaviour.
     *
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function hashedHeader(string $name): Closure
    {
        return static function (ServerRequestInterface $serverRequest) use ($name): ?string {
            $value = $serverRequest->getHeaderLine($name);
            return $value === '' ? null : hash('sha256', $value);
        };
    }

    /**
     * Extract User-Agent header.
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function userAgent(): Closure
    {
        return self::header('User-Agent');
    }

    /**
     * Extract the client IP using a TrustedProxyResolver.
     *
     * @deprecated The client IP is now the default for every rule via the Config IP
     *   resolver, so a dedicated extractor is no longer needed. Configure proxy trust
     *   once with $config->setIpResolver($trustedProxyResolver->resolve(...)) and omit
     *   the rule key (or use PortableConfig::keyIp()); both resolve the client IP.
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function clientIp(TrustedProxyResolver $trustedProxyResolver): Closure
    {
        return static fn(ServerRequestInterface $serverRequest): ?string => $trustedProxyResolver->resolve($serverRequest);
    }
}
