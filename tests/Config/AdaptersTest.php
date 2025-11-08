<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\ClosureRequestMatcher;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class AdaptersTest extends TestCase
{
    public function testClosureRequestMatcherDelegatesToClosure(): void
    {
        $matcher = new ClosureRequestMatcher(static fn($r): bool => $r->getMethod() === 'POST');
        $this->assertFalse($matcher->matches(new ServerRequest('GET', '/')));
        $this->assertTrue($matcher->matches(new ServerRequest('POST', '/')));
    }

    public function testClosureKeyExtractorDelegatesAndNormalizesToString(): void
    {
        $extractor = new ClosureKeyExtractor(static fn($r): string => (string)123);
        $this->assertSame('123', $extractor->extract(new ServerRequest('GET', '/')));
    }

    public function testClosureKeyExtractorAllowsNull(): void
    {
        $extractor = new ClosureKeyExtractor(static fn($r): ?string => null);
        $this->assertNull($extractor->extract(new ServerRequest('GET', '/')));
    }
}
