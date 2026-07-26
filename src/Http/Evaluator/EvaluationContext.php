<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http\Evaluator;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\MatchResult;
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
        public readonly bool $diagnosticsHeadersEnabled,
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

    /**
     * Extract sanitized diagnostic headers from a match when enabled.
     *
     * Matchers opt in via the `diagnostic_headers` metadata key (header => value).
     * Only `X-Phirewall-`-prefixed header names are copied, and the reserved
     * built-in names (`X-Phirewall-Matched`, `X-Phirewall-Safelist`) are rejected
     * case-insensitively, so a matcher cannot spoof security-relevant response
     * headers regardless of how a consumer merges {@see \Flowd\Phirewall\Http\FirewallResult::$headers}.
     * Values are cast from scalars with CR/LF/NUL stripped.
     *
     * @return array<string, string>
     */
    public function diagnosticHeaders(?MatchResult $matchResult): array
    {
        if (!$this->diagnosticsHeadersEnabled || !$matchResult instanceof MatchResult) {
            return [];
        }

        $declaredHeaders = $matchResult->metadata()['diagnostic_headers'] ?? null;
        if (!is_array($declaredHeaders)) {
            return [];
        }

        $headers = [];
        foreach ($declaredHeaders as $name => $value) {
            if (!is_string($name)) {
                continue;
            }

            if (!is_scalar($value)) {
                continue;
            }

            if (preg_match('/^X-Phirewall-[A-Za-z0-9-]+$/i', $name) !== 1) {
                continue;
            }

            if (in_array(strtolower($name), ['x-phirewall-matched', 'x-phirewall-safelist'], true)) {
                continue;
            }

            $headers[$name] = str_replace(["\r", "\n", "\0"], '', (string) $value);
        }

        return $headers;
    }
}
