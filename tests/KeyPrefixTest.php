<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class KeyPrefixTest extends TestCase
{
    public function testDifferentKeyPrefixesIsolateCounters(): void
    {
        $inMemoryCache = new InMemoryCache();

        // Firewall A with prefix A
        $configA = (new Config($inMemoryCache))->setKeyPrefix('customA');
        $configA->throttle('by_key', 1, 60, fn($r): string => 'k');

        $fwA = new Firewall($configA);

        // Firewall B with prefix B (same rule/key but isolated by prefix)
        $configB = (new Config($inMemoryCache))->setKeyPrefix('customB');
        $configB->throttle('by_key', 1, 60, fn($r): string => 'k');

        $fwB = new Firewall($configB);

        $serverRequest = new ServerRequest('GET', '/');

        // First request on A passes, second throttles
        $this->assertTrue($fwA->decide($serverRequest)->isPass());
        $this->assertSame(OUTCOME::THROTTLED, $fwA->decide($serverRequest)->outcome);

        // First request on B should also pass (isolation ensured by prefix)
        $this->assertTrue($fwB->decide($serverRequest)->isPass());
    }
}
