<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Response;

use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ClosureThrottledResponseFactory implements ThrottledResponseFactoryInterface
{
    /**
     * @param Closure(string,int,ServerRequestInterface):ResponseInterface $factory
     */
    public function __construct(private Closure $factory)
    {
    }

    public function create(string $rule, int $retryAfter, ServerRequestInterface $serverRequest): ResponseInterface
    {
        $f = $this->factory;
        return $f($rule, $retryAfter, $serverRequest);
    }
}
