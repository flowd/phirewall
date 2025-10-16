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
        return static function (ServerRequestInterface $request): ?string {
            $params = $request->getServerParams();
            $ip = $params['REMOTE_ADDR'] ?? null;
            if ($ip === null || $ip === '') {
                return null;
            }
            // Basic normalization to string type
            return (string) $ip;
        };
    }

    /**
     * Extract normalized HTTP method (uppercase).
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function method(): Closure
    {
        return static function (ServerRequestInterface $request): ?string {
            $method = $request->getMethod();
            return $method === '' ? null : strtoupper($method);
        };
    }

    /**
     * Extract request path (pathname only).
     * @return Closure(ServerRequestInterface): string
     */
    public static function path(): Closure
    {
        return static function (ServerRequestInterface $request): string {
            $path = $request->getUri()->getPath();
            return $path === '' ? '/' : $path;
        };
    }

    /**
     * Extract a header value by name (first value). Returns null if header missing.
     * @return Closure(ServerRequestInterface): ?string
     */
    public static function header(string $name): Closure
    {
        return static function (ServerRequestInterface $request) use ($name): ?string {
            $value = $request->getHeaderLine($name);
            return $value === '' ? null : $value;
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
    public static function clientIp(TrustedProxyResolver $resolver): Closure
    {
        return static function (ServerRequestInterface $request) use ($resolver): ?string {
            return $resolver->resolve($request);
        };
    }
}
