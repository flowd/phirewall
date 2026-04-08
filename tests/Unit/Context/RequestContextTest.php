<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Context;

use Flowd\Phirewall\Context\RecordedFailure;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use PHPUnit\Framework\TestCase;

final class RequestContextTest extends TestCase
{
    public function testContextStoresAndReturnsResult(): void
    {
        $result = FirewallResult::pass();
        $context = new RequestContext($result);

        $this->assertSame($result, $context->getResult());
    }

    public function testRecordFailureAddsToList(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force', '192.168.1.1');

        $failures = $context->getRecordedFailures();
        $this->assertCount(1, $failures);
        $this->assertInstanceOf(RecordedFailure::class, $failures[0]);
        $this->assertSame('login-brute-force', $failures[0]->ruleName);
        $this->assertSame('192.168.1.1', $failures[0]->key);
    }

    public function testHasRecordedSignalsReturnsFalseWhenEmpty(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $this->assertFalse($context->hasRecordedSignals());
    }

    public function testHasRecordedSignalsReturnsTrueAfterRecording(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force', '10.0.0.1');

        $this->assertTrue($context->hasRecordedSignals());
    }

    public function testMultipleFailuresRecorded(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force', '10.0.0.1');
        $context->recordFailure('api-abuse', 'user-42');
        $context->recordFailure('login-brute-force', '10.0.0.2');

        $failures = $context->getRecordedFailures();
        $this->assertCount(3, $failures);
        $this->assertSame('login-brute-force', $failures[0]->ruleName);
        $this->assertSame('10.0.0.1', $failures[0]->key);
        $this->assertSame('api-abuse', $failures[1]->ruleName);
        $this->assertSame('user-42', $failures[1]->key);
        $this->assertSame('login-brute-force', $failures[2]->ruleName);
        $this->assertSame('10.0.0.2', $failures[2]->key);
    }

    public function testContextWithSafelistedResult(): void
    {
        $result = FirewallResult::safelisted('health');
        $context = new RequestContext($result);

        $this->assertSame($result, $context->getResult());
        $this->assertFalse($context->hasRecordedSignals());
    }
}
