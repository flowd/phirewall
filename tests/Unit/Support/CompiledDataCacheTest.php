<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Support\CompiledDataCache;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class CompiledDataCacheTest extends TestCase
{
    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * List the compiled artifacts in a directory; glob() bypasses stream
     * wrappers, so vfs directories are listed via scandir().
     *
     * @return list<string>
     */
    private function compiledFiles(string $directory): array
    {
        $entries = @scandir($directory);
        if ($entries === false) {
            return [];
        }

        $files = [];
        foreach ($entries as $entry) {
            if (str_starts_with($entry, 'phirewall-') && str_ends_with($entry, '.php')) {
                $files[] = $directory . '/' . $entry;
            }
        }

        return $files;
    }

    /**
     * @param array<mixed> $data
     * @return array{0: callable(): array<mixed>, 1: object{count: int}}
     */
    private function countingBuilder(array $data = ['value' => 42]): array
    {
        $counter = new class () {
            public int $count = 0;
        };

        $builder = static function () use ($counter, $data): array {
            ++$counter->count;
            return $data;
        };

        return [$builder, $counter];
    }

    public function testBuildsOnceAndWritesTheCompiledArtifact(): void
    {
        $root = vfsStream::setup('cache');
        $cache = new CompiledDataCache($root->url());
        [$builder, $counter] = $this->countingBuilder();

        $first = $cache->load('crs-rules', [], $builder);
        $second = $cache->load('crs-rules', [], $builder);

        $this->assertSame(['value' => 42], $first);
        $this->assertSame(['value' => 42], $second);
        $this->assertSame(1, $counter->count);
        $this->assertCount(1, $this->compiledFiles($root->url()));
    }

    public function testLoadsFromTheCompiledFileWithoutTheBuilder(): void
    {
        $root = vfsStream::setup('cache');
        [$builder, $counter] = $this->countingBuilder(['ips' => ['203.0.113.9']]);
        (new CompiledDataCache($root->url()))->load('bad-ips', [], $builder);
        $this->assertSame(1, $counter->count);

        // A fresh process: the compiled artifact must satisfy the load alone.
        CompiledDataCache::clearProcessCache();
        $data = (new CompiledDataCache($root->url()))->load('bad-ips', [], static function (): array {
            throw new \LogicException('The builder must not run on a compiled-file hit.');
        });

        $this->assertSame(['ips' => ['203.0.113.9']], $data);
    }

    public function testRebuildsWhenASourceFileChanges(): void
    {
        $root = vfsStream::setup('cache');
        $sourceFile = vfsStream::newFile('rules.conf')->at($root)->setContent('rule v1');
        $sourceFile->lastModified(1_000_000);

        $cache = new CompiledDataCache($root->url());
        [$builder, $counter] = $this->countingBuilder();

        $cache->load('rules', [$sourceFile->url()], $builder);
        $this->assertSame(1, $counter->count);

        // Unchanged source: both the process cache and the artifact stay valid.
        $cache->load('rules', [$sourceFile->url()], $builder);
        $this->assertSame(1, $counter->count);

        // A newer source mtime invalidates even the warm process cache. PHP's
        // stat cache would hide the in-process mtime change; between real
        // requests it plays no role.
        $sourceFile->lastModified(1_000_100);
        clearstatcache();
        $cache->load('rules', [$sourceFile->url()], $builder);
        $this->assertSame(2, $counter->count);
    }

    public function testCorruptCompiledFileFallsBackToTheBuilder(): void
    {
        $root = vfsStream::setup('cache');
        [$builder, $counter] = $this->countingBuilder();
        (new CompiledDataCache($root->url()))->load('rules', [], $builder);

        $compiledFiles = $this->compiledFiles($root->url());
        $this->assertCount(1, $compiledFiles);
        file_put_contents($compiledFiles[0], '<?php this is not valid php');

        CompiledDataCache::clearProcessCache();
        $data = (new CompiledDataCache($root->url()))->load('rules', [], $builder);

        $this->assertSame(['value' => 42], $data);
        $this->assertSame(2, $counter->count);
    }

    public function testWrongShapeArtifactFallsBackToTheBuilder(): void
    {
        $root = vfsStream::setup('cache');
        [$builder, $counter] = $this->countingBuilder();
        (new CompiledDataCache($root->url()))->load('rules', [], $builder);

        $compiledFiles = $this->compiledFiles($root->url());
        $this->assertCount(1, $compiledFiles);

        // Parses fine, but data is not an array.
        file_put_contents($compiledFiles[0], "<?php return ['sourcesMtime' => 0, 'data' => 'not-an-array'];");
        CompiledDataCache::clearProcessCache();
        (new CompiledDataCache($root->url()))->load('rules', [], $builder);
        $this->assertSame(2, $counter->count);

        // Parses fine, but the artifact is not the expected structure at all.
        file_put_contents($compiledFiles[0], '<?php return 42;');
        CompiledDataCache::clearProcessCache();
        (new CompiledDataCache($root->url()))->load('rules', [], $builder);
        $this->assertSame(3, $counter->count);
    }

    public function testRebuildsWhenTheSourceMtimeMovesBackwards(): void
    {
        $root = vfsStream::setup('cache');
        $sourceFile = vfsStream::newFile('rules.conf')->at($root)->setContent('rule v2');
        $sourceFile->lastModified(1_000_100);

        $cache = new CompiledDataCache($root->url());
        [$builder, $counter] = $this->countingBuilder();
        $cache->load('rules', [$sourceFile->url()], $builder);
        $this->assertSame(1, $counter->count);

        // A rollback restores an OLDER mtime; the equality check must
        // still treat it as a change.
        $sourceFile->lastModified(1_000_000);
        clearstatcache();
        $cache->load('rules', [$sourceFile->url()], $builder);
        $this->assertSame(2, $counter->count);
    }

    public function testRejectsTopLevelObjects(): void
    {
        $root = vfsStream::setup('cache');
        $cache = new CompiledDataCache($root->url());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('plain data');
        $cache->load('rules', [], static fn(): array => [new \stdClass()]);
    }

    public function testUnwritableDirectoryStillServesTheData(): void
    {
        $root = vfsStream::setup('cache');
        $root->chmod(0o555);
        $cache = new CompiledDataCache($root->url());
        [$builder, $counter] = $this->countingBuilder();

        $this->assertSame(['value' => 42], $cache->load('rules', [], $builder));
        $this->assertSame([], $this->compiledFiles($root->url()));

        // The process memoization still prevents a rebuild per call.
        $cache->load('rules', [], $builder);
        $this->assertSame(1, $counter->count);
    }

    public function testMissingDirectoryIsCreatedForTheArtifact(): void
    {
        $root = vfsStream::setup('cache');
        $cache = new CompiledDataCache($root->url() . '/nested/cache');
        [$builder] = $this->countingBuilder();

        $cache->load('rules', [], $builder);

        $this->assertCount(1, $this->compiledFiles($root->url() . '/nested/cache'));
    }

    public function testRejectsObjectsInTheBuiltData(): void
    {
        $root = vfsStream::setup('cache');
        $cache = new CompiledDataCache($root->url());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('plain data');
        $cache->load('rules', [], static fn(): array => ['nested' => ['object' => new \stdClass()]]);
    }

    public function testIdentifiersAreSanitizedIntoDistinctFilesInsideTheDirectory(): void
    {
        $root = vfsStream::setup('cache');
        $cache = new CompiledDataCache($root->url());
        [$builder] = $this->countingBuilder();

        $cache->load('../escape/attempt', [], $builder);
        $cache->load('good.id', [], $builder);

        $compiledFiles = $this->compiledFiles($root->url());
        $this->assertCount(2, $compiledFiles);
        $this->assertFalse($root->hasChild('escape'));
    }
}
