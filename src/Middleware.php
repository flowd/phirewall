<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Http\ResponseFactoryResolver;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class Middleware implements MiddlewareInterface
{
    private Http\Firewall $firewall;

    private ResponseFactoryInterface $responseFactory;

    public function __construct(
        private Config $config,
        ?ResponseFactoryInterface $responseFactory = null,
    ) {
        $this->responseFactory = $responseFactory ?? ResponseFactoryResolver::detect();
        $this->firewall = new Http\Firewall($this->config);
    }

    public function process(ServerRequestInterface $serverRequest, RequestHandlerInterface $requestHandler): ResponseInterface
    {
        $firewallResult = $this->firewall->decide($serverRequest);

        if ($firewallResult->isBlocked()) {
            // Build a blocking response (403/429) using configured factories or PSR-17 if available
            if ($firewallResult->outcome === Http\Outcome::THROTTLED) {
                $retryAfter = $firewallResult->retryAfter ?? 1;
                $factory = $this->config->getThrottledResponseFactory();
                if ($factory instanceof \Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface) {
                    $response = $factory->create($firewallResult->rule ?? 'unknown', $retryAfter, $serverRequest);
                } else {
                    $response = $this->responseFactory->createResponse(429)->withHeader('Content-Type', 'text/plain');
                }

                // Ensure Retry-After is present
                if ($response->getHeaderLine('Retry-After') === '') {
                    $response = $response->withHeader('Retry-After', (string)max(1, $retryAfter));
                }
            } else {
                $factory = $this->config->getBlocklistedResponseFactory();
                if ($factory instanceof \Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface) {
                    $response = $factory->create($firewallResult->rule ?? 'unknown', $firewallResult->blockType ?? 'blocklist', $serverRequest);
                } else {
                    $response = $this->responseFactory->createResponse(403)->withHeader('Content-Type', 'text/plain');
                }
            }

            // Apply standard and computed headers
            foreach ($firewallResult->headers as $name => $value) {
                $response = $response->withHeader($name, $value);
            }

            return $response;
        }

        // Pass-through: call next handler and apply headers (safelisted or ratelimit)
        $response = $requestHandler->handle($serverRequest);
        foreach ($firewallResult->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
