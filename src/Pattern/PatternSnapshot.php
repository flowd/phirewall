<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

/**
 * Snapshot of patterns from a backend, keyed by a version/etag for caching.
 */
final readonly class PatternSnapshot
{
    /**
     * @param list<PatternEntry> $entries
     */
    public function __construct(
        public array $entries,
        public string|int $version,
        public string $source,
    ) {
    }
}
