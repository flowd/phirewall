<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Flowd\Phirewall\Owasp\CoreRule;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all argument values and names from both query parameters and parsed body.
 *
 * The number of arguments is attacker-controlled, so collection short-circuits once
 * {@see CoreRule::MAX_VALUES} entries have been gathered to bound per-request cost.
 */
final readonly class ArgsCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        if (!$this->collectFrom($serverRequest->getQueryParams(), $collected)) {
            return $collected;
        }

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            $this->collectFrom($parsed, $collected);
        }

        return $collected;
    }

    /**
     * Append values and names from a parameter map, short-circuiting at {@see CoreRule::MAX_VALUES}.
     *
     * @param array<array-key, mixed> $parameters
     * @param list<string> $collected
     * @return bool false when the cap was reached and collection should stop
     */
    private function collectFrom(array $parameters, array &$collected): bool
    {
        foreach ($parameters as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $nestedValue) {
                    if (is_scalar($nestedValue)) {
                        $collected[] = (string) $nestedValue;
                        if (count($collected) >= CoreRule::MAX_VALUES) {
                            return false;
                        }
                    }
                }
            } elseif (is_scalar($value)) {
                $collected[] = (string) $value;
                if (count($collected) >= CoreRule::MAX_VALUES) {
                    return false;
                }
            }

            $collected[] = (string) $key; // include argument names for name-based checks
            if (count($collected) >= CoreRule::MAX_VALUES) {
                return false;
            }
        }

        return true;
    }
}
