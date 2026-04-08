<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Throughput and scaling benchmarks. Assertions use very conservative floors
 * so these pass reliably on any CI runner. The point is to catch regressions,
 * not to measure absolute throughput.
 */
#[Group('performance')]
final class PerformanceBenchmarkTest extends TestCase
{
    protected function setUp(): void
    {
        if (getenv('PHIREWALL_RUN_BENCHMARKS') !== '1') {
            $this->markTestSkipped('Set PHIREWALL_RUN_BENCHMARKS=1 to run performance benchmarks.');
        }
    }

    // ── Throughput ────────────────────────────────────────────────────────

    public function testDecideBaselineThroughput(): void
    {
        $firewall = new Firewall(new Config(new InMemoryCache()));
        $serverRequest = new ServerRequest('GET', '/');

        $opsPerSec = $this->measureOpsPerSecond(fn(): FirewallResult => $firewall->decide($serverRequest), 5000);

        $this->assertGreaterThan(2000, $opsPerSec, sprintf('Baseline: %.0f ops/sec', $opsPerSec));
    }

    public function testDecideWithMixedRulesThroughput(): void
    {
        $config = new Config(new InMemoryCache());
        for ($i = 0; $i < 5; ++$i) {
            $config->safelists->add('safe-' . $i, fn($r): false => false);
        }

        for ($i = 0; $i < 5; ++$i) {
            $config->blocklists->add('block-' . $i, fn($r): false => false);
        }

        for ($i = 0; $i < 5; ++$i) {
            $config->throttles->add('throttle-' . $i, 10000, 60, fn($r): string => '127.0.0.1');
        }

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '127.0.0.1']);

        $opsPerSec = $this->measureOpsPerSecond(fn(): FirewallResult => $firewall->decide($serverRequest), 2000);

        $this->assertGreaterThan(500, $opsPerSec, sprintf('Mixed rules: %.0f ops/sec', $opsPerSec));
    }

    public function testSnapshotBlocklistMatcherThroughput(): void
    {
        $entries = [];
        for ($i = 0; $i < 500; ++$i) {
            $entries[] = new PatternEntry(PatternKind::IP, "10.0." . intdiv($i, 256) . "." . ($i % 256));
        }

        for ($i = 0; $i < 100; ++$i) {
            $entries[] = new PatternEntry(PatternKind::CIDR, sprintf('172.%d.0.0/16', $i));
        }

        $config = new Config(new InMemoryCache());
        $config->blocklists->patternBlocklist('big-list', $entries);

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '8.8.8.8']);

        $opsPerSec = $this->measureOpsPerSecond(fn(): FirewallResult => $firewall->decide($serverRequest), 1000);

        $this->assertGreaterThan(100, $opsPerSec, sprintf('600 patterns: %.0f ops/sec', $opsPerSec));
    }

    // ── Scaling ──────────────────────────────────────────────────────────

    public function testThrottleScalesLinearly(): void
    {
        $time10 = $this->measureDecideTimeForRuleCount(10, 500);
        $time100 = $this->measureDecideTimeForRuleCount(100, 500);

        // 100 rules should take less than 20x the time of 10 rules
        $this->assertLessThan(
            $time10 * 20,
            $time100,
            sprintf('Scaling: 10 rules=%.2fms, 100 rules=%.2fms (ratio=%.1fx)', $time10 * 1000, $time100 * 1000, $time100 / max($time10, 0.0001)),
        );
    }

    public function testSafelistShortCircuitsBlocklistEvaluation(): void
    {
        // With 100 blocklist rules but a safelist that matches first,
        // performance should be close to having no blocklists
        $configSafe = new Config(new InMemoryCache());
        $configSafe->safelists->add('always', fn($r): bool => true);
        for ($i = 0; $i < 100; ++$i) {
            $configSafe->blocklists->add('block-' . $i, fn($r): bool => $r->getUri()->getPath() === '/path-' . $i);
        }

        $configBare = new Config(new InMemoryCache());
        $configBare->safelists->add('always', fn($r): bool => true);

        $serverRequest = new ServerRequest('GET', '/test');
        $firewallSafe = new Firewall($configSafe);
        $firewallBare = new Firewall($configBare);
        $timeSafe = $this->measureOpsPerSecond(fn(): FirewallResult => $firewallSafe->decide($serverRequest), 1000);
        $timeBare = $this->measureOpsPerSecond(fn(): FirewallResult => $firewallBare->decide($serverRequest), 1000);

        // Safelist short-circuit: performance should be within 5x of bare
        $this->assertGreaterThan($timeBare / 5, $timeSafe, 'Safelist should short-circuit blocklist evaluation');
    }

    // ── Memory ───────────────────────────────────────────────────────────

    public function testInMemoryCacheMemoryBounded(): void
    {
        $inMemoryCache = new InMemoryCache();
        $memBefore = memory_get_usage(true);

        for ($i = 0; $i < 10000; ++$i) {
            $inMemoryCache->set('key-' . $i, 'value-' . $i, 3600);
        }

        $memAfter = memory_get_usage(true);
        $usedMb = ($memAfter - $memBefore) / 1024 / 1024;

        $this->assertLessThan(50, $usedMb, sprintf('InMemoryCache 10k entries: %.1f MB', $usedMb));
    }

    public function testInMemoryPatternBackendMemoryBounded(): void
    {
        $entries = [];
        for ($i = 0; $i < 5000; ++$i) {
            $entries[] = new PatternEntry(PatternKind::IP, "10." . intdiv($i, 65536) . "." . (intdiv($i, 256) % 256) . "." . ($i % 256));
        }

        $memBefore = memory_get_usage(true);
        $inMemoryPatternBackend = new InMemoryPatternBackend($entries);
        $inMemoryPatternBackend->consume();
        // force snapshot creation
        $memAfter = memory_get_usage(true);
        $usedMb = ($memAfter - $memBefore) / 1024 / 1024;

        $this->assertLessThan(30, $usedMb, sprintf('InMemoryPatternBackend 5k entries: %.1f MB', $usedMb));
    }

    public function testConfigManyRulesMemoryBounded(): void
    {
        $memBefore = memory_get_usage(true);
        $config = new Config(new InMemoryCache());

        for ($i = 0; $i < 500; ++$i) {
            $config->safelists->add('safe-' . $i, fn($r): false => false);
            $config->blocklists->add('block-' . $i, fn($r): false => false);
            $config->throttles->add('throttle-' . $i, 100, 60, fn($r): string => '127.0.0.1');
        }

        $memAfter = memory_get_usage(true);
        $usedMb = ($memAfter - $memBefore) / 1024 / 1024;

        $this->assertLessThan(20, $usedMb, sprintf('Config 1500 rules: %.1f MB', $usedMb));
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private function measureOpsPerSecond(callable $fn, int $iterations): float
    {
        // Warmup
        for ($i = 0; $i < min(10, $iterations); ++$i) {
            $fn();
        }

        $start = hrtime(true);
        for ($i = 0; $i < $iterations; ++$i) {
            $fn();
        }

        $elapsed = (hrtime(true) - $start) / 1e9;
        return $iterations / max($elapsed, 0.0001);
    }

    private function measureDecideTimeForRuleCount(int $ruleCount, int $iterations): float
    {
        $config = new Config(new InMemoryCache());
        for ($i = 0; $i < $ruleCount; ++$i) {
            $config->throttles->add('t-' . $i, 100000, 60, fn($r): string => '127.0.0.1');
        }

        $firewall = new Firewall($config);
        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '127.0.0.1']);

        // Warmup
        for ($i = 0; $i < 5; ++$i) {
            $firewall->decide($serverRequest);
        }

        $start = hrtime(true);
        for ($i = 0; $i < $iterations; ++$i) {
            $firewall->decide($serverRequest);
        }

        return (hrtime(true) - $start) / 1e9;
    }
}
