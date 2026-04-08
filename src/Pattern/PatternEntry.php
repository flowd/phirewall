<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

/**
 * Immutable value object representing a single block pattern with optional expiry and metadata.
 */
final readonly class PatternEntry
{
    /**
     * @param PatternKind $kind Pattern kind (IP, CIDR, path, header, etc.)
     * @param string $value Pattern value; for header_* kinds this is the match expression
     * @param string|null $target Target field (e.g., header name for header_* kinds)
     * @param int|null $expiresAt Unix timestamp when this entry expires
     * @param int|null $addedAt Unix timestamp when this entry was created/seen
     * @param array<string, scalar> $metadata Optional metadata for diagnostics
     */
    public function __construct(
        public PatternKind $kind,
        public string $value,
        public ?string $target = null,
        public ?int $expiresAt = null,
        public ?int $addedAt = null,
        public array $metadata = [],
    ) {
    }

    /**
     * Compute a unique identity key for deduplication (kind + target + value).
     */
    public function key(): string
    {
        return $this->kind->value . ':' . $this->target . ':' . $this->value;
    }

    /**
     * Merge this entry with an incoming entry of the same identity.
     *
     * Keeps the longer expiry and the most recent addedAt timestamp.
     * Preserves the existing entry's kind, value, target, and metadata.
     */
    public function merge(self $incoming): self
    {
        $expiresAt = $this->expiresAt === null || $incoming->expiresAt === null
            ? null
            : max($this->expiresAt, $incoming->expiresAt);

        $addedAt = $this->addedAt;
        if ($incoming->addedAt !== null && ($this->addedAt === null || $incoming->addedAt > $this->addedAt)) {
            $addedAt = $incoming->addedAt;
        }

        return new self(
            kind: $this->kind,
            value: $this->value,
            target: $this->target,
            expiresAt: $expiresAt,
            addedAt: $addedAt,
            metadata: $this->metadata,
        );
    }
}
