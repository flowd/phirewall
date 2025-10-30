<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Closure;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\SimpleCache\CacheInterface;

final class Config
{
    /** @var array<string, Closure> */
    private array $safelists = [];

    /** @var array<string, Closure> */
    private array $blocklists = [];

    /** @var array<string, array{limit:int,period:int,key:Closure}> */
    private array $throttles = [];

    /** @var array<string, array{threshold:int,period:int,ban:int,filter:Closure,key:Closure}> */
    private array $fail2bans = [];

    /** @var array<string, array{period:int,filter:Closure,key:Closure}> */
    private array $tracks = [];

    /** @var null|Closure(string,string,ServerRequestInterface):ResponseInterface */
    private $blocklistedResponseFactory = null;

    /** @var null|Closure(string,int,ServerRequestInterface):ResponseInterface */
    private $throttledResponseFactory = null;

    private bool $rateLimitHeadersEnabled = false;

    private string $keyPrefix = 'phirewall';

    /**
     * Lightweight diagnostics counters for testing and observability.
     * Structure: [category => ['total' => int, 'by_rule' => array<string,int>]]
     * @var array<string, array{total:int, by_rule: array<string,int> }>
     */
    private array $diagnosticsCounters = [];

    public function __construct(
        public readonly CacheInterface $cache,
        public readonly ?EventDispatcherInterface $dispatcher = null,
    ) {
    }

    /**
     * Safelist: if callback returns true for the request, bypass all other checks.
     * @param Closure $callback fn(ServerRequestInterface): bool
     */
    public function safelist(string $name, Closure $callback): self
    {
        $this->safelists[$name] = $callback;
        return $this;
    }

    /**
     * Blocklist: if callback returns true, block the request (403)
     * @param Closure $callback fn(ServerRequestInterface): bool
     */
    public function blocklist(string $name, Closure $callback): self
    {
        $this->blocklists[$name] = $callback;
        return $this;
    }

    /**
     * Throttle: limit requests per key within a period.
     * @param Closure $key fn(ServerRequestInterface): string|null returns unique key or null to skip
     */
    public function throttle(string $name, int $limit, int $period, Closure $key): self
    {
        $this->throttles[$name] = [
            'limit' => $limit,
            'period' => $period,
            'key' => $key,
        ];
        return $this;
    }

    /**
     * Fail2ban: if filter matches threshold times within period, ban key for ban seconds.
     * @param Closure $filter fn(ServerRequestInterface): bool
     * @param Closure $key fn(ServerRequestInterface): string|null
     */
    public function fail2ban(string $name, int $threshold, int $period, int $ban, Closure $filter, Closure $key): self
    {
        $this->fail2bans[$name] = [
            'threshold' => $threshold,
            'period' => $period,
            'ban' => $ban,
            'filter' => $filter,
            'key' => $key,
        ];
        return $this;
    }

    /**
     * Track: if filter returns true, increment a counter for the given key within period and emit event.
     * Does not affect request outcome.
     * @param Closure $filter fn(ServerRequestInterface): bool
     * @param Closure $key fn(ServerRequestInterface): string|null
     */
    public function track(string $name, int $period, Closure $filter, Closure $key): self
    {
        $this->tracks[$name] = [
            'period' => $period,
            'filter' => $filter,
            'key' => $key,
        ];
        return $this;
    }

    /**
     * Set a custom response factory for blocklisted/forbidden responses (also used by fail2ban).
     * Factory signature: fn(string $rule, string $type, ServerRequestInterface $request): ResponseInterface
     * where $type is 'blocklist' or 'fail2ban'.
     */
    public function blocklistedResponse(Closure $factory): self
    {
        $this->blocklistedResponseFactory = $factory;
        return $this;
    }

    /**
     * Set a custom response factory for throttled responses.
     * Factory signature: fn(string $rule, int $retryAfter, ServerRequestInterface $request): ResponseInterface
     */
    public function throttledResponse(Closure $factory): self
    {
        $this->throttledResponseFactory = $factory;
        return $this;
    }

    /** @return array<string, Closure> */
    public function getSafelists(): array
    {
        return $this->safelists;
    }

    /** @return array<string, Closure> */
    public function getBlocklists(): array
    {
        return $this->blocklists;
    }

    /** @return array<string, array{limit:int,period:int,key:Closure}> */
    public function getThrottles(): array
    {
        return $this->throttles;
    }

    /** @return array<string, array{threshold:int,period:int,ban:int,filter:Closure,key:Closure}> */
    public function getFail2Bans(): array
    {
        return $this->fail2bans;
    }

    /** @return array<string, array{period:int,filter:Closure,key:Closure}> */
    public function getTracks(): array
    {
        return $this->tracks;
    }

    /** @return null|Closure(string,string,ServerRequestInterface):ResponseInterface */
    public function getBlocklistedResponseFactory(): ?Closure
    {
        return $this->blocklistedResponseFactory;
    }

    /** @return null|Closure(string,int,ServerRequestInterface):ResponseInterface */
    public function getThrottledResponseFactory(): ?Closure
    {
        return $this->throttledResponseFactory;
    }

    public function enableRateLimitHeaders(bool $enabled = true): self
    {
        $this->rateLimitHeadersEnabled = $enabled;
        return $this;
    }

    public function rateLimitHeadersEnabled(): bool
    {
        return $this->rateLimitHeadersEnabled;
    }

    public function setKeyPrefix(string $prefix): self
    {
        $normalized = trim($prefix);
        if ($normalized === '') {
            throw new \InvalidArgumentException('Key prefix cannot be empty');
        }
        $this->keyPrefix = rtrim($normalized, ':');
        return $this;
    }

    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }

    /**
     * Increment diagnostics counter for a given category and optional rule name.
     */
    public function incrementDiagnosticsCounter(string $category, ?string $rule = null): void
    {
        if (!isset($this->diagnosticsCounters[$category])) {
            $this->diagnosticsCounters[$category] = ['total' => 0, 'by_rule' => []];
        }
        $this->diagnosticsCounters[$category]['total']++;
        if ($rule !== null) {
            if (!isset($this->diagnosticsCounters[$category]['by_rule'][$rule])) {
                $this->diagnosticsCounters[$category]['by_rule'][$rule] = 0;
            }
            $this->diagnosticsCounters[$category]['by_rule'][$rule]++;
        }
    }

    /**
     * Reset all diagnostics counters (useful for unit tests).
     */
    public function resetDiagnosticsCounters(): void
    {
        $this->diagnosticsCounters = [];
    }

    /**
     * Get a snapshot of diagnostics counters.
     * @return array<string, array{total:int, by_rule: array<string,int> }>
     */
    public function getDiagnosticsCounters(): array
    {
        return $this->diagnosticsCounters;
    }
}
