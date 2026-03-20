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
 */
final readonly class SuspiciousHeadersMatcher implements RequestMatcherInterface
{
    public const DEFAULT_REQUIRED_HEADERS = ['Accept', 'Accept-Language', 'Accept-Encoding'];

    /** @var list<string> */
    private array $requiredHeaders;

    /**
     * @param list<string> $requiredHeaders Headers that must be present. Defaults to Accept, Accept-Language, Accept-Encoding.
     */
    public function __construct(array $requiredHeaders = [])
    {
        $headers = $requiredHeaders !== [] ? $requiredHeaders : self::DEFAULT_REQUIRED_HEADERS;
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
