<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

interface PatternBackendInterface
{
    public const MAX_ENTRIES_DEFAULT = 10000;

    public function consume(): PatternSnapshot;

    public function append(PatternEntry $patternEntry): void;

    public function pruneExpired(): void;

    public function type(): string;

    /**
     * @return array<string, int|float|string|bool|array<int, string>>
     */
    public function capabilities(): array;
}
