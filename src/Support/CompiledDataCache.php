<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Support;

/**
 * Two-level cache for expensive-to-build, var_export-able plain data.
 *
 * Preset packages use this to avoid re-parsing large data sources (rule sets,
 * IP feeds) on every request: a per-process memoization serves warm workers,
 * and a compiled PHP artifact in the given directory serves cold ones through
 * OPcache. Both levels revalidate against the newest mtime of the source
 * files, so editing a source rebuilds on the next request.
 *
 * The artifact is executed as PHP via include, so the directory must be a
 * trusted, non-web-accessible cache location (the same trust level as a
 * compiled DI container). Only plain data (scalars, null, nested arrays) is
 * accepted; objects are rejected instead of being revived through
 * __set_state(). That rejection guards the write path - the read path
 * deliberately performs no re-validation, so protection against a tampered
 * artifact is solely the directory trust. A read failure, a corrupt
 * artifact, or an unwritable directory silently degrades to rebuilding via
 * the builder: a cache must never take the firewall down.
 */
final class CompiledDataCache
{
    /** @var array<string, array<string, array{sourcesMtime: int, data: array<mixed>}>> Keyed by directory, then identifier. */
    private static array $processCache = [];

    public function __construct(private readonly string $directory)
    {
    }

    /**
     * Load the data for the identifier, building and caching it when stale.
     *
     * @param string $identifier Developer-defined and bounded; never derive it
     *                           from request input (one artifact per identifier).
     * @param list<string> $sourceFiles Files whose newest mtime invalidates the
     *                                  cache; an empty list disables invalidation
     *                                  (bump the identifier to bust).
     * @param callable(): array<mixed> $builder Builds the data on a cache miss.
     * @return array<mixed>
     * @throws \InvalidArgumentException When the builder returns non-plain data.
     */
    public function load(string $identifier, array $sourceFiles, callable $builder): array
    {
        $sourcesMtime = $this->latestMtime($sourceFiles);

        // Nested keys (directory, then identifier) so neither can collide via a
        // shared delimiter.
        $memoized = self::$processCache[$this->directory][$identifier] ?? null;
        if ($memoized !== null && $memoized['sourcesMtime'] === $sourcesMtime) {
            return $memoized['data'];
        }

        $compiledFile = $this->compiledFilePath($identifier);
        $data = $this->readCompiled($compiledFile, $sourcesMtime);

        if ($data === null) {
            $data = $builder();
            $this->assertPlainData($data);
            $this->writeCompiled($compiledFile, $sourcesMtime, $data);
        }

        self::$processCache[$this->directory][$identifier] = ['sourcesMtime' => $sourcesMtime, 'data' => $data];

        return $data;
    }

    /**
     * Drop the per-process memoization (long-running workers after a
     * deployment, test isolation).
     */
    public static function clearProcessCache(): void
    {
        self::$processCache = [];
    }

    /**
     * @param list<string> $sourceFiles
     */
    private function latestMtime(array $sourceFiles): int
    {
        $latest = 0;
        foreach ($sourceFiles as $sourceFile) {
            $mtime = @filemtime($sourceFile);
            if (is_int($mtime) && $mtime > $latest) {
                $latest = $mtime;
            }
        }

        return $latest;
    }

    private function compiledFilePath(string $identifier): string
    {
        $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', $identifier) ?? 'data';

        return $this->directory . '/phirewall-' . $safeName . '-' . substr(sha1($identifier), 0, 8) . '.php';
    }

    /**
     * @return array<mixed>|null
     */
    private function readCompiled(string $compiledFile, int $sourcesMtime): ?array
    {
        if (!is_file($compiledFile)) {
            return null;
        }

        try {
            $compiled = @include $compiledFile;
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($compiled)
            || ($compiled['sourcesMtime'] ?? null) !== $sourcesMtime
            || !is_array($compiled['data'] ?? null)
        ) {
            return null;
        }

        return $compiled['data'];
    }

    /**
     * Write the artifact atomically (temp file + rename); failures degrade
     * silently to per-process memoization.
     *
     * @param array<mixed> $data
     */
    private function writeCompiled(string $compiledFile, int $sourcesMtime, array $data): void
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0o775, true) && !is_dir($this->directory)) {
            return;
        }

        $php = "<?php\n\n// Compiled by Flowd\\Phirewall\\Support\\CompiledDataCache; delete to rebuild.\nreturn "
            . var_export(['sourcesMtime' => $sourcesMtime, 'data' => $data], true)
            . ";\n";

        $temporaryFile = $compiledFile . '.' . uniqid('tmp', true);
        if (@file_put_contents($temporaryFile, $php) === false) {
            @unlink($temporaryFile);
            return;
        }

        if (!@rename($temporaryFile, $compiledFile)) {
            @unlink($temporaryFile);
            return;
        }

        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($compiledFile, true);
        }
    }

    /**
     * @param array<mixed> $data
     */
    private function assertPlainData(array $data): void
    {
        foreach ($data as $value) {
            if (is_array($value)) {
                $this->assertPlainData($value);
                continue;
            }

            if ($value !== null && !is_scalar($value)) {
                throw new \InvalidArgumentException(
                    'CompiledDataCache only accepts plain data (scalars, null, nested arrays), got ' . get_debug_type($value) . '.',
                );
            }
        }
    }
}
