<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class Middleware implements MiddlewareInterface
{
    private Http\Firewall $firewall;

    public function __construct(
        private Config $config,
        private ResponseFactoryInterface $responseFactory,
    ) {
        $this->firewall = new Http\Firewall($this->config);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $result = $this->firewall->decide($request);

        if ($result->isBlocked()) {
            // Build a blocking response (403/429) using configured factories or PSR-17 if available
            if ($result->outcome === Http\FirewallResult::OUTCOME_THROTTLED) {
                $retryAfter = $result->retryAfter ?? 1;
                $factory = $this->config->getThrottledResponseFactory();
                if ($factory !== null) {
                    $response = $factory($result->rule ?? 'unknown', $retryAfter, $request);
                } else {
                    $response = $this->responseFactory->createResponse(429)->withHeader('Content-Type', 'text/plain');
                }
                // Ensure Retry-After is present
                if ($response->getHeaderLine('Retry-After') === '') {
                    $response = $response->withHeader('Retry-After', (string)max(1, $retryAfter));
                }
            } else {
                $factory = $this->config->getBlocklistedResponseFactory();
                if ($factory !== null) {
                    $response = $factory($result->rule ?? 'unknown', $result->blockType ?? 'blocklist', $request);
                } else {
                    $response = $this->responseFactory->createResponse(403)->withHeader('Content-Type', 'text/plain');
                }
            }

            // Apply standard and computed headers
            foreach ($result->headers as $name => $value) {
                $response = $response->withHeader($name, $value);
            }
            return $response;
        }

        // Pass-through: call next handler and apply headers (safelisted or ratelimit)
        $response = $handler->handle($request);
        foreach ($result->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
