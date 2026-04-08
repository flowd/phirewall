<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__, 2);
require $projectRoot . '/vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

function phpt_handler(int $statusCode = 200): RequestHandlerInterface
{
    return new class ($statusCode) implements RequestHandlerInterface {
        public function __construct(private readonly int $statusCode)
        {
        }

        public function handle(ServerRequestInterface $request): ResponseInterface
        {
            return new Response($this->statusCode, ['X-Handler' => 'ok']);
        }
    };
}

function phpt_request(
    string $method,
    string $uri,
    array $serverParams = [],
    array $headers = [],
): ServerRequest {
    return new ServerRequest($method, $uri, $headers, null, '1.1', $serverParams);
}

function phpt_middleware(Config $config): Middleware
{
    return new Middleware($config, new Psr17Factory());
}
