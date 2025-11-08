<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Closure;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ClosureKeyExtractor implements KeyExtractorInterface
{
    /**
     * @param Closure(ServerRequestInterface):(?string) $callback
     */
    public function __construct(private Closure $callback)
    {
    }

    public function extract(ServerRequestInterface $serverRequest): ?string
    {
        $cb = $this->callback;
        $value = $cb($serverRequest);
        return $value === null ? null : (string)$value;
    }
}
