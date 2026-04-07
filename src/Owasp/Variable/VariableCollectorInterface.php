<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects target values from a PSR-7 request for a specific OWASP CRS variable type.
 */
interface VariableCollectorInterface
{
    /**
     * Collect values for this variable from the given request.
     *
     * @return list<string>
     */
    public function collect(ServerRequestInterface $serverRequest): array;
}
