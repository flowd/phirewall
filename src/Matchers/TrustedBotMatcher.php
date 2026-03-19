<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\KeyExtractors;
use Psr\Http\Message\ServerRequestInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Safelists verified search engine bots via reverse DNS (RDNS) verification.
 *
 * Verification flow:
 *  1. Check if User-Agent matches a known bot pattern (case-insensitive substring).
 *  2. Perform reverse DNS: resolve IP -> hostname via gethostbyaddr().
 *  3. Verify hostname ends with the expected domain suffix.
 *  4. Forward-confirm: resolve hostname -> IPs via gethostbynamel() and check any match.
 *  5. Match (allow) only when all checks pass.
 *
 * Results are cached using PSR-16 (if provided) to avoid repeated DNS lookups
 * for the same IP. The default TTL is 86400 seconds (24 hours).
 *
 * This prevents fake bots: any client can send "Googlebot" as a UA, but only
 * Google's real crawlers will have IPs that resolve to *.googlebot.com.
 *
 * WARNING: Without a PSR-16 cache, each request with a bot-like User-Agent
 * triggers blocking DNS lookups (gethostbyaddr + gethostbynamel/dns_get_record).
 * In production, always provide a cache instance to avoid latency and DNS load.
 */
final class TrustedBotMatcher implements RequestMatcherInterface
{
    /**
     * Built-in verified search engine bots.
     *
     * @var list<array{ua: string, hostname: string}>
     */
    public const BUILT_IN_BOTS = [
        ['ua' => 'googlebot',             'hostname' => '.googlebot.com'],
        ['ua' => 'google-inspectiontool', 'hostname' => '.googlebot.com'],
        ['ua' => 'bingbot',               'hostname' => '.search.msn.com'],
        ['ua' => 'msnbot',                'hostname' => '.search.msn.com'],
        ['ua' => 'baiduspider',           'hostname' => '.baidu.com'],
        ['ua' => 'duckduckbot',           'hostname' => '.duckduckgo.com'],
        ['ua' => 'yandexbot',             'hostname' => '.yandex.com'],
        ['ua' => 'yandex.com/bots',       'hostname' => '.yandex.com'],
        ['ua' => 'slurp',                 'hostname' => '.yahoo.net'],
        ['ua' => 'applebot',              'hostname' => '.applebot.apple.com'],
    ];

    private const CACHE_PREFIX = 'phirewall:trusted_bot:';

    private const DEFAULT_CACHE_TTL = 86400;

    private const NEGATIVE_CACHE_TTL = 300;

    /** @var list<array{ua: string, hostname: string}> */
    private readonly array $bots;

    /** @var callable(string): string */
    private $reverseResolve;

    /** @var callable(string): list<string> */
    private $forwardResolve;

    /** @var callable(ServerRequestInterface): ?string */
    private $ipResolver;

    /**
     * @param list<array{ua: string, hostname: string}> $additionalBots
     * @param (callable(string): string)|null $reverseResolve Override for gethostbyaddr() (for testing).
     * @param (callable(string): list<string>)|null $forwardResolve Override for gethostbynamel() (for testing).
     * @param (callable(ServerRequestInterface): ?string)|null $ipResolver Custom IP resolver. Defaults to KeyExtractors::ip().
     * @param CacheInterface|null $cache PSR-16 cache for DNS results. Avoids repeated lookups for the same IP.
     * @param positive-int $cacheTtl Cache TTL in seconds. Default: 86400 (24 hours).
     */
    public function __construct(
        array $additionalBots = [],
        ?callable $reverseResolve = null,
        ?callable $forwardResolve = null,
        ?callable $ipResolver = null,
        private readonly ?CacheInterface $cache = null,
        private readonly int $cacheTtl = self::DEFAULT_CACHE_TTL,
    ) {
        foreach ($additionalBots as $additionalBot) {
            if (!isset($additionalBot['ua'], $additionalBot['hostname']) || !is_string($additionalBot['ua']) || !is_string($additionalBot['hostname'])) {
                throw new \InvalidArgumentException('Each bot entry must have string keys "ua" and "hostname".');
            }

            if (trim($additionalBot['ua']) === '' || trim($additionalBot['hostname']) === '') {
                throw new \InvalidArgumentException('Bot "ua" and "hostname" must not be empty.');
            }

            if (!str_starts_with($additionalBot['hostname'], '.')) {
                throw new \InvalidArgumentException('Bot hostname suffix must start with a dot (e.g. ".googlebot.com") to prevent subdomain spoofing.');
            }
        }

        if ($cacheTtl <= 0) {
            throw new \InvalidArgumentException('Cache TTL must be greater than 0.');
        }

        $this->bots = [...self::BUILT_IN_BOTS, ...$additionalBots];
        $this->reverseResolve = $reverseResolve ?? static fn(string $ip): string => (string) @gethostbyaddr($ip);
        $this->forwardResolve = $forwardResolve ?? static function (string $host): array {
            $ips = [];
            // A records (IPv4)
            $a = @gethostbynamel($host);
            if ($a !== false) {
                $ips = $a;
            }

            // AAAA records (IPv6)
            $aaaa = @dns_get_record($host, DNS_AAAA);
            if ($aaaa !== false) {
                foreach ($aaaa as $record) {
                    if (isset($record['ipv6'])) {
                        $ips[] = $record['ipv6'];
                    }
                }
            }

            return $ips;
        };
        $this->ipResolver = $ipResolver ?? KeyExtractors::ip();
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $userAgent = strtolower($serverRequest->getHeaderLine('User-Agent'));
        if ($userAgent === '') {
            return MatchResult::noMatch();
        }

        $ip = ($this->ipResolver)($serverRequest);
        if ($ip === null) {
            return MatchResult::noMatch();
        }

        foreach ($this->bots as $bot) {
            if (!str_contains($userAgent, strtolower($bot['ua']))) {
                continue;
            }

            if ($this->verifyBot($ip, $bot['hostname'])) {
                return MatchResult::matched('trusted_bot', ['bot_ua' => $bot['ua'], 'bot_hostname' => $bot['hostname']]);
            }

            // UA matched but verification failed — fake bot; do NOT safelist
            return MatchResult::noMatch();
        }

        return MatchResult::noMatch();
    }

    private function verifyBot(string $ip, string $expectedHostnameSuffix): bool
    {
        // Validate and normalize IP before DNS lookups and cache keying
        $ipBinary = @inet_pton($ip);
        if ($ipBinary === false) {
            return false;
        }

        $normalizedIp = (string) @inet_ntop($ipBinary);
        $cacheKey = self::CACHE_PREFIX . hash('sha256', $normalizedIp . '|' . $expectedHostnameSuffix);

        if ($this->cache instanceof \Psr\SimpleCache\CacheInterface) {
            $cached = $this->cache->get($cacheKey);
            if (is_bool($cached)) {
                return $cached;
            }
        }

        $result = $this->verifyRdns($normalizedIp, $expectedHostnameSuffix);

        if ($this->cache instanceof \Psr\SimpleCache\CacheInterface) {
            // Positive results cached for full TTL; negative results cached briefly
            // to allow quick recovery from transient DNS failures
            $ttl = $result ? $this->cacheTtl : self::NEGATIVE_CACHE_TTL;
            $this->cache->set($cacheKey, $result, $ttl);
        }

        return $result;
    }

    private function verifyRdns(string $ip, string $expectedHostnameSuffix): bool
    {
        $hostname = ($this->reverseResolve)($ip);

        // gethostbyaddr returns the original IP on failure
        if ($hostname === $ip || $hostname === '') {
            return false;
        }

        if (!str_ends_with(strtolower($hostname), strtolower($expectedHostnameSuffix))) {
            return false;
        }

        // Forward-confirm: hostname must resolve back to the original IP.
        // Normalize both sides via inet_pton to handle IPv6 representation differences
        // (e.g. "2001:db8::1" vs "2001:0db8:0000:0000:0000:0000:0000:0001").
        $resolvedIps = ($this->forwardResolve)($hostname);
        $ipBinary = @inet_pton($ip);
        if ($ipBinary === false) {
            return false;
        }

        foreach ($resolvedIps as $resolvedIp) {
            $resolvedBinary = @inet_pton($resolvedIp);
            if ($resolvedBinary !== false && $resolvedBinary === $ipBinary) {
                return true;
            }
        }

        return false;
    }
}
