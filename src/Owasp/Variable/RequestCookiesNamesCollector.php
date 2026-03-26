<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie names from the request.
 */
final readonly class RequestCookiesNamesCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        foreach (array_keys($serverRequest->getCookieParams()) as $key) {
            $collected[] = (string) $key;
        }

        return $collected;
    }
}
