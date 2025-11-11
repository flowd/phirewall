<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use PHPUnit\Framework\TestCase;

final class SecRuleLoaderLogicalLinesTest extends TestCase
{
    public function testLogicalLinesJoinFor933210(): void
    {
        $root = dirname(__DIR__, 2);
        $path = $root . '/examples/owasp_crs_basic/REQUEST-933-APPLICATION-ATTACK-PHP.conf';
        $this->assertFileExists($path);
        $content = (string)file_get_contents($path);

        $reflectionClass = new \ReflectionClass(SecRuleLoader::class);
        $reflectionMethod = $reflectionClass->getMethod('logicalLines');
        $reflectionMethod->setAccessible(true);
        /** @var string[] $lines */
        $lines = $reflectionMethod->invoke(null, $content);

        $joined = null;
        foreach ($lines as $line) {
            if (str_contains($line, 'id:933210')) {
                $joined = $line;
                break;
            }
        }

        $this->assertNotNull($joined, 'Expected logicalLines to join rule 933210 into a single line');
        $this->assertStringStartsWith('SecRule ', $joined);
        $this->assertStringContainsString('"@rx ', $joined);
        $this->assertStringContainsString('"id:933210', $joined);
    }
}
