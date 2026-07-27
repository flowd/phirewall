<?php

declare(strict_types=1);

/**
 * Example 32: CompiledDataCache - skip re-parsing expensive preset data.
 *
 * Under PHP-FPM the firewall Config is built on every request. A preset that
 * parses a large data source during that build (an OWASP rule set, an IP feed)
 * pays the parsing cost per request. CompiledDataCache removes it with two
 * levels: a per-process memoization for warm workers and a compiled PHP
 * artifact (served by OPcache) for cold ones. Both revalidate against the
 * newest mtime of the source files, so editing a source rebuilds once.
 *
 * The artifact directory is executed as PHP, so treat it like a compiled DI
 * container: trusted and outside the web root. Only plain data (scalars,
 * null, nested arrays) is cacheable; hydrating objects from the array is the
 * caller's job. Cache failures degrade silently to rebuilding - the cache can
 * never take the firewall down.
 *
 * This example:
 *   1. parses a small rule file through the cache (builder runs once);
 *   2. loads again in the same process (memoized, no parse);
 *   3. simulates a fresh worker (compiled artifact serves the load);
 *   4. edits the source file (the next load re-parses).
 */

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Support\CompiledDataCache;

$demoDir = sys_get_temp_dir() . '/phirewall_compiled_cache_example_' . bin2hex(random_bytes(4));
mkdir($demoDir . '/cache', 0o775, true);

// A stand-in for an expensive source: one rule per line.
$sourceFile = $demoDir . '/rules.txt';
file_put_contents($sourceFile, "block /.env\nblock /.git\n");

$parseCount = 0;
$parseRules = function () use ($sourceFile, &$parseCount): array {
    ++$parseCount;
    echo "  ... parsing {$sourceFile}\n";
    $lines = file($sourceFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

    return array_map(static fn(string $line): array => ['raw' => $line], $lines);
};

$cache = new CompiledDataCache($demoDir . '/cache');

echo "=== 1. First load: the builder parses the source ===\n";
$rules = $cache->load('demo-rules', [$sourceFile], $parseRules);
echo '  ' . count($rules) . " rules, parse count: {$parseCount}\n\n";

echo "=== 2. Second load in the same process: memoized ===\n";
$cache->load('demo-rules', [$sourceFile], $parseRules);
echo "  parse count still: {$parseCount}\n\n";

echo "=== 3. Fresh worker: the compiled artifact serves the load ===\n";
CompiledDataCache::clearProcessCache(); // simulates a new PHP process
$cache->load('demo-rules', [$sourceFile], $parseRules);
echo "  parse count still: {$parseCount} (loaded from the artifact via include/OPcache)\n\n";

echo "=== 4. Source edited: the next load re-parses ===\n";
file_put_contents($sourceFile, "block /.env\nblock /.git\nblock /.aws/credentials\n");
touch($sourceFile, time() + 1); // ensure a newer mtime despite 1s granularity
clearstatcache();
CompiledDataCache::clearProcessCache();
$rules = $cache->load('demo-rules', [$sourceFile], $parseRules);
echo '  ' . count($rules) . " rules, parse count: {$parseCount}\n\n";

$artifacts = array_filter(scandir($demoDir . '/cache') ?: [], static fn(string $f): bool => str_starts_with($f, 'phirewall-'));
echo "Artifact on disk: " . implode(', ', $artifacts) . "\n";

// Cleanup
foreach ($artifacts as $artifact) {
    unlink($demoDir . '/cache/' . $artifact);
}

unlink($sourceFile);
rmdir($demoDir . '/cache');
rmdir($demoDir);
echo "Demo files cleaned up.\n";
