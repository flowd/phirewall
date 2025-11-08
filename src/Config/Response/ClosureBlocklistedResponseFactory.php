<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Response;

use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ClosureBlocklistedResponseFactory implements BlocklistedResponseFactoryInterface
{
    /**
     * @param Closure(string,string,ServerRequestInterface):ResponseInterface $factory
     */
    public function __construct(private Closure $factory)
    {
    }

    public function create(string $rule, string $type, ServerRequestInterface $serverRequest): ResponseInterface
    {
        $f = $this->factory;
        return $f($rule, $type, $serverRequest);
    }
}
