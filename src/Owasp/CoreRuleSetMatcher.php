<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Adapter that evaluates an OWASP CoreRuleSet against a PSR-7 request.
 * Implements RequestMatcherInterface so it can be used as a Blocklist matcher.
 */
final readonly class CoreRuleSetMatcher implements RequestMatcherInterface
{
    public function __construct(private CoreRuleSet $coreRuleSet)
    {
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $id = $this->coreRuleSet->match($serverRequest);
        if ($id === null) {
            return MatchResult::noMatch();
        }

        $meta = ['owasp_rule_id' => $id];
        $rule = $this->coreRuleSet->getRule($id);
        if ($rule instanceof CoreRule) {
            $msg = $rule->actions['msg'] ?? null;
            if (is_string($msg) && $msg !== '') {
                $meta['msg'] = $msg;
            }
        }

        return MatchResult::matched('owasp', $meta);
    }

    public function enable(int $id): void
    {
        $this->coreRuleSet->enable($id);
    }

    public function disable(int $id): void
    {
        $this->coreRuleSet->disable($id);
    }

    public function isEnabled(int $id): bool
    {
        return $this->coreRuleSet->isEnabled($id);
    }
}
