<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Closure;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Common key extractor helpers you can pass directly into Config::throttle(), ::fail2ban() or ::track().
 *
 * These helpers intentionally avoid trusting proxy headers by default. For trusted proxy/client IP resolution,
 * use KeyExtractors::clientIp() with a TrustedProxyResolver.
 */
final class KeyExtractors
{
    /**
     * Extract client IP from REMOTE_ADDR server param. Does not trust proxies.
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
     * Extract a header value by name (first value). Returns null if header missing.
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
     * Extract client IP using a TrustedProxyResolver. Safe for deployments behind trusted proxies.
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function clientIp(TrustedProxyResolver $trustedProxyResolver): Closure
    {
        return static fn(ServerRequestInterface $serverRequest): ?string => $trustedProxyResolver->resolve($serverRequest);
    }
}
