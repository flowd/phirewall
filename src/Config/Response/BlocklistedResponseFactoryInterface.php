<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Response;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface BlocklistedResponseFactoryInterface
{
    public function create(string $rule, string $type, ServerRequestInterface $serverRequest): ResponseInterface;
}
