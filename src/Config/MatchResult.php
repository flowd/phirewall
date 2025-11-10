<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

/**
 * Result of evaluating a request against a matcher.
 * Carries a binary decision and optional metadata for diagnostics.
 */
final class MatchResult
{
    /** @param array<string, scalar> $metadata */
    private function __construct(
        private bool $matched,
        private string $source,
        private array $metadata = [],
    ) {
    }

    /** @param array<string, scalar> $metadata */
    public static function matched(string $source, array $metadata = []): self
    {
        return new self(true, $source, $metadata);
    }

    public static function noMatch(): self
    {
        return new self(false, '', []);
    }

    public function isMatch(): bool
    {
        return $this->matched;
    }

    /**
     * Category/source of the match (e.g., 'owasp', 'custom'). Empty when no match.
     */
    public function source(): string
    {
        return $this->source;
    }

    /**
     * @return array<string, scalar>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }
}
