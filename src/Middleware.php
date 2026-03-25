<?php

declare(strict_types=1);

namespace Flowd\Phirewall;

use Flowd\Phirewall\Context\RequestContext;
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

        // Attach request context so application code can record fail2ban signals
        $context = new RequestContext($firewallResult);
        $serverRequest = $serverRequest->withAttribute(RequestContext::ATTRIBUTE_NAME, $context);

        // Pass-through: call next handler and apply headers (safelisted or ratelimit)
        $response = $requestHandler->handle($serverRequest);

        // Process any fail2ban signals recorded by the handler
        if ($context->hasRecordedSignals()) {
            try {
                $this->processContextSignals($context, $serverRequest);
            } catch (\Throwable $throwable) {
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
            }
        }

        foreach ($firewallResult->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /**
     * Process all recorded failure signals from the request context.
     */
    private function processContextSignals(RequestContext $requestContext, ServerRequestInterface $serverRequest): void
    {
        foreach ($requestContext->getRecordedFailures() as $recordedFailure) {
            $this->firewall->processRecordedFailure(
                $recordedFailure->ruleName,
                $recordedFailure->key,
                $serverRequest,
            );
        }
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
            $throttledFactory = $this->config->throttledResponseFactory;
            if ($throttledFactory instanceof \Flowd\Phirewall\Config\Response\ThrottledResponseFactoryInterface) {
                $response = $throttledFactory->create($firewallResult->rule ?? 'unknown', $retryAfter, $serverRequest);
            } else {
                $response = $this->responseFactory->createResponse(429)->withHeader('Content-Type', 'text/plain');
            }

            // Ensure Retry-After is present
            if ($response->getHeaderLine('Retry-After') === '') {
                $response = $response->withHeader('Retry-After', (string)max(1, $retryAfter));
            }
        } else {
            $blocklistedFactory = $this->config->blocklistedResponseFactory;
            if ($blocklistedFactory instanceof \Flowd\Phirewall\Config\Response\BlocklistedResponseFactoryInterface) {
                $response = $blocklistedFactory->create($firewallResult->rule ?? 'unknown', $firewallResult->blockType ?? 'blocklist', $serverRequest);
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
