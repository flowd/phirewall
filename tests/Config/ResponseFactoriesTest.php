<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Config;

use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Config\Response\ClosureThrottledResponseFactory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class ResponseFactoriesTest extends TestCase
{
    public function testClosureBlocklistedResponseFactoryForwardsParameters(): void
    {
        $factory = new ClosureBlocklistedResponseFactory(
            static fn(string $rule, string $type, \Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface => new Response(451, ['X-Rule' => $rule, 'X-Type' => $type])
        );
        $response = $factory->create('r1', 'blocklist', new ServerRequest('GET', '/'));
        $this->assertSame(451, $response->getStatusCode());
        $this->assertSame('r1', $response->getHeaderLine('X-Rule'));
        $this->assertSame('blocklist', $response->getHeaderLine('X-Type'));
    }

    public function testClosureThrottledResponseFactoryForwardsParameters(): void
    {
        $factory = new ClosureThrottledResponseFactory(
            static fn(string $rule, int $retryAfter, \Psr\Http\Message\ServerRequestInterface $serverRequest): \Psr\Http\Message\ResponseInterface => new Response(429, ['X-Rule' => $rule, 'X-Retry' => (string)$retryAfter])
        );
        $response = $factory->create('t1', 7, new ServerRequest('GET', '/'));
        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('t1', $response->getHeaderLine('X-Rule'));
        $this->assertSame('7', $response->getHeaderLine('X-Retry'));
    }
}
