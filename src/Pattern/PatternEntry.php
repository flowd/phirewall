<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

/**
 * Immutable value object representing a single block pattern with optional expiry and metadata.
 */
final readonly class PatternEntry
{
    /**
     * @param string $kind One of: ip, cidr, path_exact, path_prefix, path_regex, header_exact, header_regex, request_regex
     * @param string $value Pattern value; for header_* kinds this is the match expression
     * @param string|null $target Target field (e.g., header name for header_* kinds)
     * @param int|null $expiresAt Unix timestamp when this entry expires
     * @param int|null $addedAt Unix timestamp when this entry was created/seen
     * @param array<string, scalar> $metadata Optional metadata for diagnostics
     */
    public function __construct(
        public string $kind,
        public string $value,
        public ?string $target = null,
        public ?int $expiresAt = null,
        public ?int $addedAt = null,
        public array $metadata = [],
    ) {
    }
}
