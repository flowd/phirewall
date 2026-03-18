<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Blocks requests whose User-Agent matches known attack tools, vulnerability scanners,
 * and exploit frameworks.
 *
 * Ships with a curated default list. Pass your own list to the constructor to
 * extend, replace, or reduce it.
 *
 * Usage:
 *   // Use defaults
 *   $config->blocklists->knownScanners();
 *
 *   // Add custom patterns on top of defaults
 *   $config->blocklists->knownScanners('scanners', [...self::DEFAULT_PATTERNS, 'my-tool']);
 *
 *   // Use only your own list
 *   new KnownScannerMatcher(['my-tool', 'other-tool']);
 */
final readonly class KnownScannerMatcher implements RequestMatcherInterface
{
    /**
     * Default list of known attack tools and scanners (case-insensitive substrings).
     *
     * @var list<string>
     */
    public const DEFAULT_PATTERNS = [
        'sqlmap',
        'nikto',
        'nmap',
        'masscan',
        'zmeu',
        'havij',
        'acunetix',
        'nessus',
        'openvas',
        'w3af',
        'dirbuster',
        'gobuster',
        'wfuzz',
        'hydra',
        'medusa',
        'burpsuite',
        'burp suite',
        'skipfish',
        'whatweb',
        'metasploit',
        'msfconsole',
        'nuclei',
        'ffuf',
        'feroxbuster',
        'joomscan',
        'wpscan',
    ];

    /** @var list<string> */
    private array $patterns;

    /**
     * @param list<string>|null $patterns UA substrings to block (case-insensitive). Defaults to DEFAULT_PATTERNS.
     */
    public function __construct(?array $patterns = null)
    {
        $rawPatterns = $patterns ?? self::DEFAULT_PATTERNS;
        $normalized = [];
        foreach ($rawPatterns as $rawPattern) {
            $rawPattern = strtolower(trim($rawPattern));
            if ($rawPattern === '') {
                throw new \InvalidArgumentException('KnownScannerMatcher patterns must not contain empty strings.');
            }

            $normalized[] = $rawPattern;
        }

        $this->patterns = $normalized;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $userAgent = strtolower($serverRequest->getHeaderLine('User-Agent'));

        if ($userAgent === '') {
            return MatchResult::noMatch();
        }

        foreach ($this->patterns as $pattern) {
            if (str_contains($userAgent, $pattern)) {
                return MatchResult::matched('known_scanner', ['ua_pattern' => $pattern]);
            }
        }

        return MatchResult::noMatch();
    }
}
