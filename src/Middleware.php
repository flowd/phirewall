<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Phirewall\Store\CounterStoreInterface;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class Middleware implements MiddlewareInterface
{
    public function __construct(
        private Config $config,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $pendingRateLimitHeaders = null;
        // 0) Track: passive metrics (does not affect outcome)
        foreach ($this->config->getTracks() as $name => $rule) {
            if ($rule['filter']($request) === true) {
                $key = $rule['key']($request);
                if ($key !== null) {
                    $counterKey = $this->trackKey($name, (string)$key);
                    $count = $this->increment($counterKey, $rule['period']);
                    $this->config->incrementDiagnosticsCounter('track_hit', $name);
                    $this->dispatch(new TrackHit(
                        rule: $name,
                        key: (string)$key,
                        period: $rule['period'],
                        count: $count,
                        request: $request,
                    ));
                }
            }
        }

        // 1) Safelist: if any matches, short-circuit and pass through
        foreach ($this->config->getSafelists() as $name => $callback) {
            if ($callback($request) === true) {
                $this->dispatch(new SafelistMatched($name, $request));
                $this->config->incrementDiagnosticsCounter('safelisted', $name);
                $response = $handler->handle($request);
                return $response->withHeader('X-Phirewall-Safelist', $name);
            }
        }

        // 2) Blocklist: if any matches, block 403
        foreach ($this->config->getBlocklists() as $name => $callback) {
            if ($callback($request) === true) {
                $this->dispatch(new BlocklistMatched($name, $request));
                $this->config->incrementDiagnosticsCounter('blocklisted', $name);
                $response = $this->forbidden($name, 'blocklist', $request);
                return $response;
            }
        }

        $cache = $this->config->cache;

        // 3) Fail2Ban: block if banned; otherwise track failures and possibly ban
        foreach ($this->config->getFail2Bans() as $name => $rule) {
            $key = $rule['key']($request);
            if ($key === null) {
                continue;
            }
            $banKey = $this->banKey($name, (string)$key);
            if ($cache->has($banKey)) {
                $this->config->incrementDiagnosticsCounter('fail2ban_blocked', $name);
                $response = $this->forbidden($name, 'fail2ban', $request);
                return $response;
            }
            if ($rule['filter']($request) === true) {
                // increment failure counter
                $failKey = $this->failKey($name, (string)$key);
                $count = $this->increment($failKey, $rule['period']);
                $this->config->incrementDiagnosticsCounter('fail2ban_fail_hit', $name);
                if ($count >= $rule['threshold']) {
                    $cache->set($banKey, 1, $rule['ban']);
                    $this->config->incrementDiagnosticsCounter('fail2ban_banned', $name);
                    $this->dispatch(new Fail2BanBanned(
                        rule: $name,
                        key: (string)$key,
                        threshold: $rule['threshold'],
                        period: $rule['period'],
                        banSeconds: $rule['ban'],
                        count: $count,
                        request: $request,
                    ));
                }
            }
        }

        // 4) Throttle
        foreach ($this->config->getThrottles() as $name => $rule) {
            $key = $rule['key']($request);
            if ($key === null) {
                continue;
            }
            $counterKey = $this->throttleKey($name, (string)$key);
            $count = $this->increment($counterKey, $rule['period']);
            $limit = (int) $rule['limit'];
            $retryAfter = $this->ttlRemaining($counterKey);
            $remaining = max(0, $limit - $count);

            if ($count > $limit) {
                $this->dispatch(new ThrottleExceeded(
                    rule: $name,
                    key: (string)$key,
                    limit: $limit,
                    period: $rule['period'],
                    count: $count,
                    retryAfter: $retryAfter,
                    request: $request,
                ));
                $this->config->incrementDiagnosticsCounter('throttle_exceeded', $name);
                $response = $this->tooManyRequests($name, $retryAfter, $request);
                if ($this->config->rateLimitHeadersEnabled()) {
                    $response = $response
                        ->withHeader('X-RateLimit-Limit', (string)$limit)
                        ->withHeader('X-RateLimit-Remaining', '0')
                        ->withHeader('X-RateLimit-Reset', (string)max(1, $retryAfter));
                }
                return $response;
            }

            // Not exceeded: capture headers for later if enabled (first applicable throttle wins)
            if ($this->config->rateLimitHeadersEnabled() && $pendingRateLimitHeaders === null) {
                $pendingRateLimitHeaders = [
                    'limit' => $limit,
                    'remaining' => $remaining,
                    'reset' => max(1, $retryAfter),
                ];
            }
        }

        // All good
        $response = $handler->handle($request);
        $this->config->incrementDiagnosticsCounter('passed');
        if ($this->config->rateLimitHeadersEnabled() && $pendingRateLimitHeaders !== null) {
            $response = $response
                ->withHeader('X-RateLimit-Limit', (string)$pendingRateLimitHeaders['limit'])
                ->withHeader('X-RateLimit-Remaining', (string)$pendingRateLimitHeaders['remaining'])
                ->withHeader('X-RateLimit-Reset', (string)$pendingRateLimitHeaders['reset']);
        }
        return $response;
    }

    private function forbidden(string $rule, string $type = 'blocklist', ?ServerRequestInterface $request = null): ResponseInterface
    {
        $factory = $this->config->getBlocklistedResponseFactory();
        if ($factory !== null && $request !== null) {
            $response = $factory($rule, $type, $request);
        } else {
            $response = new Response(403);
            $response = $response->withHeader('Content-Type', 'text/plain');
        }
        // Ensure standard headers are present
        $response = $response
            ->withHeader('X-Phirewall', $type)
            ->withHeader('X-Phirewall-Matched', $rule);
        return $response;
    }

    private function tooManyRequests(string $rule, int $retryAfter, ?ServerRequestInterface $request = null): ResponseInterface
    {
        $factory = $this->config->getThrottledResponseFactory();
        if ($factory !== null && $request !== null) {
            $response = $factory($rule, $retryAfter, $request);
        } else {
            $response = new Response(429);
            $response = $response->withHeader('Content-Type', 'text/plain');
        }
        // Ensure standard headers are present
        $response = $response
            ->withHeader('X-Phirewall', 'throttle')
            ->withHeader('X-Phirewall-Matched', $rule);
        if ($response->getHeaderLine('Retry-After') === '') {
            $response = $response->withHeader('Retry-After', (string)max(1, $retryAfter));
        }
        return $response;
    }

    private function increment(string $key, int $period): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->increment($key, $period);
        }
        // Generic PSR-16 fallback (non-atomic)
        $value = (int)($cache->get($key, 0));
        $value++;
        if ($value === 1) {
            $cache->set($key, $value, $period);
        } else {
            // keep existing TTL; we cannot extend reliably, so set small ttl if missing
            $cache->set($key, $value);
        }
        return $value;
    }

    private function ttlRemaining(string $key): int
    {
        $cache = $this->config->cache;
        if ($cache instanceof CounterStoreInterface) {
            return $cache->ttlRemaining($key);
        }
        // No standard way to get TTL; return a conservative default 60
        return 60;
    }

    private function throttleKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':throttle:' . $safeName . ':' . $safeKey;
    }

    private function failKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':fail2ban:fail:' . $safeName . ':' . $safeKey;
    }

    private function banKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':fail2ban:ban:' . $safeName . ':' . $safeKey;
    }

    private function dispatch(object $event): void
    {
        $dispatcher = $this->config->dispatcher;
        if ($dispatcher !== null) {
            $dispatcher->dispatch($event);
        }
    }

    private function trackKey(string $name, string $key): string
    {
        $safeName = $this->normalizeKeyComponent($name);
        $safeKey = $this->normalizeKeyComponent($key);
        return $this->config->getKeyPrefix() . ':track:' . $safeName . ':' . $safeKey;
    }

    private function normalizeKeyComponent(string $value): string
    {
        $original = trim($value);
        if ($original === '') {
            return 'empty';
        }
        // Allow only safe characters to avoid cache poisoning and key explosion.
        $sanitized = preg_replace('/[^A-Za-z0-9._:-]/', '_', $original);
        if ($sanitized === null) {
            $sanitized = 'invalid';
        }
        // Collapse repeated underscores
        $sanitized = preg_replace('/_+/', '_', $sanitized) ?? $sanitized;
        // Cap length; append short hash to retain uniqueness for long inputs
        $max = 120;
        if (strlen($sanitized) > $max) {
            $hash = substr(sha1($original), 0, 12);
            $sanitized = substr($sanitized, 0, $max - 13) . '-' . $hash;
        }
        return $sanitized;
    }
}
