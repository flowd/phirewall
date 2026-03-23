<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Response;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

final readonly class Psr17BlocklistedResponseFactory implements BlocklistedResponseFactoryInterface
{
    public function __construct(private ResponseFactoryInterface $responseFactory, private ?StreamFactoryInterface $streamFactory = null, private string $bodyText = 'Forbidden')
    {
    }

    public function create(string $rule, string $type, ServerRequestInterface $serverRequest): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(403)
            ->withHeader('Content-Type', 'text/plain');

        if ($this->streamFactory instanceof \Psr\Http\Message\StreamFactoryInterface) {
            $body = $this->streamFactory->createStream($this->bodyText);
            $response = $response->withBody($body);
        }

        return $response;
    }
}
