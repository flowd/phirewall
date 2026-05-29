<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Context;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Context\RecordedSignal;
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

    public function testRecordFailureWithExplicitKey(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force', '192.168.1.1');

        $signals = $context->getRecordedSignals();
        $this->assertCount(1, $signals);
        $this->assertInstanceOf(RecordedSignal::class, $signals[0]);
        $this->assertSame('login-brute-force', $signals[0]->ruleName);
        $this->assertSame(BanType::Fail2Ban, $signals[0]->banType);
        $this->assertSame('192.168.1.1', $signals[0]->key);
    }

    public function testRecordFailureWithoutKeyDefersToRuleExtractor(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force');

        $signals = $context->getRecordedSignals();
        $this->assertCount(1, $signals);
        $this->assertSame('login-brute-force', $signals[0]->ruleName);
        $this->assertNull($signals[0]->key, "Null key tells Firewall to use the rule's own keyExtractor");
    }

    public function testRecordHitProducesAllow2BanSignal(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordHit('expensive-endpoint', 'tenant-42');

        $signals = $context->getRecordedSignals();
        $this->assertCount(1, $signals);
        $this->assertSame('expensive-endpoint', $signals[0]->ruleName);
        $this->assertSame(BanType::Allow2Ban, $signals[0]->banType);
        $this->assertSame('tenant-42', $signals[0]->key);
    }

    public function testRecordHitWithoutKeyDefersToRuleExtractor(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordHit('expensive-endpoint');

        $signals = $context->getRecordedSignals();
        $this->assertCount(1, $signals);
        $this->assertNull($signals[0]->key);
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

    public function testMultipleSignalsAcrossBanTypesAreRecorded(): void
    {
        $context = new RequestContext(FirewallResult::pass());

        $context->recordFailure('login-brute-force', '10.0.0.1');
        $context->recordHit('expensive-endpoint');
        $context->recordFailure('login-brute-force', '10.0.0.2');

        $signals = $context->getRecordedSignals();
        $this->assertCount(3, $signals);
        $this->assertSame(BanType::Fail2Ban, $signals[0]->banType);
        $this->assertSame('10.0.0.1', $signals[0]->key);
        $this->assertSame(BanType::Allow2Ban, $signals[1]->banType);
        $this->assertNull($signals[1]->key);
        $this->assertSame(BanType::Fail2Ban, $signals[2]->banType);
        $this->assertSame('10.0.0.2', $signals[2]->key);
    }

    public function testContextWithSafelistedResult(): void
    {
        $result = FirewallResult::safelisted('health');
        $context = new RequestContext($result);

        $this->assertSame($result, $context->getResult());
        $this->assertFalse($context->hasRecordedSignals());
    }
}
