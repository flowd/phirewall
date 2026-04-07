<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\DecisionPath;
use Flowd\Phirewall\Throttle\FixedWindowCounter;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mutable context passed through the evaluator pipeline for a single request.
 *
 * Carries shared configuration, the normalizer closure, the fixed-window counter,
 * and mutable state that evaluators update as they reach decisions.
 */
final class EvaluationContext
{
    public DecisionPath $decisionPath = DecisionPath::Passed;

    public ?string $decisionRule = null;

    /** @var array<string, string>|null */
    public ?array $pendingRateLimitHeaders = null;

    /**
     * @param \Closure(string): string $normalize
     */
    public function __construct(
        public readonly Config $config,
        public readonly \Closure $normalize,
        public readonly bool $responseHeadersEnabled,
        public readonly bool $rateLimitHeadersEnabled,
        public readonly bool $owaspDiagnosticsHeaderEnabled,
        public readonly FixedWindowCounter $counter,
    ) {
    }

    /**
     * Dispatch a PSR-14 event if an event dispatcher is configured.
     */
    public function dispatch(object $event): void
    {
        $dispatcher = $this->config->eventDispatcher;
        if ($dispatcher instanceof EventDispatcherInterface) {
            $dispatcher->dispatch($event);
        }
    }

    /**
     * Build X-Phirewall response headers when response headers are enabled.
     *
     * @return array<string, string>
     */
    public function responseHeaders(string $type, string $rule): array
    {
        return $this->responseHeadersEnabled
            ? ['X-Phirewall' => $type, 'X-Phirewall-Matched' => $rule]
            : [];
    }
}
