<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Blocks requests missing standard HTTP headers that real browsers typically send.
 *
 * Many attack tools and scrapers omit headers like Accept, Accept-Language,
 * or Accept-Encoding. Note that some privacy tools, embedded browsers, and
 * API clients may also omit these headers legitimately.
 *
 * Ships with a curated default header set. Passing your own list to the
 * constructor replaces the defaults; to extend them, merge your headers with
 * DEFAULT_REQUIRED_HEADERS, and to require a different (including smaller) set,
 * pass that set explicitly.
 *
 * Usage:
 *   // Use defaults
 *   $config->blocklists->suspiciousHeaders();
 *
 *   // Add custom headers on top of defaults by merging with DEFAULT_REQUIRED_HEADERS.
 *   // The first argument is the rule name; the second is the header list.
 *   $config->blocklists->suspiciousHeaders('custom-suspicious-headers', [...SuspiciousHeadersMatcher::DEFAULT_REQUIRED_HEADERS, 'X-Request-ID']);
 *
 *   // Require only your own list (no defaults)
 *   new SuspiciousHeadersMatcher(['X-Custom-Auth', 'X-Request-ID']);
 */
final readonly class SuspiciousHeadersMatcher implements RequestMatcherInterface
{
    public const DEFAULT_REQUIRED_HEADERS = ['Accept', 'Accept-Language', 'Accept-Encoding'];

    /** @var list<string> */
    private array $requiredHeaders;

    /**
     * @param list<string>|null $requiredHeaders Headers that must be present. Defaults to DEFAULT_REQUIRED_HEADERS
     *                                           (Accept, Accept-Language, Accept-Encoding) when null. A non-empty list
     *                                           overrides the defaults; an explicit empty list requires no headers.
     */
    public function __construct(?array $requiredHeaders = null)
    {
        $headers = $requiredHeaders ?? self::DEFAULT_REQUIRED_HEADERS;
        foreach ($headers as $header) {
            if (!is_string($header) || trim($header) === '') {
                throw new \InvalidArgumentException('Required headers must be non-empty strings.');
            }
        }

        $this->requiredHeaders = $headers;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        foreach ($this->requiredHeaders as $requiredHeader) {
            if ($serverRequest->getHeaderLine($requiredHeader) === '') {
                return MatchResult::matched('suspicious_headers', ['missing' => $requiredHeader]);
            }
        }

        return MatchResult::noMatch();
    }
}
