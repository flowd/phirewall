<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Http\ResponseFactoryResolver;
use Psr\EventDispatcher\EventDispatcherInterface;
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
        try {
            $firewallResult = $this->firewall->decide($serverRequest);
        } catch (\Throwable $throwable) {
            return $this->handleError($throwable, $serverRequest, $requestHandler);
        }

        if ($firewallResult->isBlocked()) {
            return $this->buildBlockedResponse($firewallResult, $serverRequest);
        }

        // Pass-through: call next handler and apply headers (safelisted or ratelimit)
        $response = $requestHandler->handle($serverRequest);
        foreach ($firewallResult->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    private function handleError(
        \Throwable $throwable,
        ServerRequestInterface $serverRequest,
        RequestHandlerInterface $requestHandler,
    ): ResponseInterface {
        if (!$this->config->isFailOpen()) {
            throw $throwable;
        }

        try {
            $dispatcher = $this->config->eventDispatcher;
            if ($dispatcher instanceof EventDispatcherInterface) {
                $dispatcher->dispatch(new FirewallError($throwable, $serverRequest));
            }
        } catch (\Throwable) {
            // Swallow dispatcher/listener errors to preserve fail-open behavior.
        }

        return $requestHandler->handle($serverRequest);
    }

    private function buildBlockedResponse(
        Http\FirewallResult $firewallResult,
        ServerRequestInterface $serverRequest,
    ): ResponseInterface {
        if ($firewallResult->outcome === Http\Outcome::THROTTLED) {
            $retryAfter = $firewallResult->retryAfter ?? 1;
            $factory = $this->config->getThrottledResponseFactory();
            if ($factory instanceof Config\Response\ThrottledResponseFactoryInterface) {
                $response = $factory->create($firewallResult->rule ?? 'unknown', $retryAfter, $serverRequest);
            } else {
                $response = $this->responseFactory->createResponse(429)->withHeader('Content-Type', 'text/plain');
            }

            if ($response->getHeaderLine('Retry-After') === '') {
                $response = $response->withHeader('Retry-After', (string) max(1, $retryAfter));
            }
        } else {
            $factory = $this->config->getBlocklistedResponseFactory();
            if ($factory instanceof Config\Response\BlocklistedResponseFactoryInterface) {
                $response = $factory->create($firewallResult->rule ?? 'unknown', $firewallResult->blockType ?? 'blocklist', $serverRequest);
            } else {
                $response = $this->responseFactory->createResponse(403)->withHeader('Content-Type', 'text/plain');
            }
        }

        foreach ($firewallResult->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
