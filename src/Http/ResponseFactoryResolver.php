<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Psr\Http\Message\ResponseFactoryInterface;

/**
 * Finds a PSR-17 ResponseFactory from common implementations so the middleware can
 * work out-of-the-box when a known PSR-7/17 package is installed.
 */
final class ResponseFactoryResolver
{
    public static function detect(): ResponseFactoryInterface
    {
        foreach (self::factoryClasses() as $class) {
            if (class_exists($class)) {
                /** @var ResponseFactoryInterface $factory */
                $factory = new $class();
                return $factory;
            }
        }

        throw new \RuntimeException('No PSR-17 ResponseFactory could be auto-detected. Install e.g. nyholm/psr7 or pass your own factory to the middleware.');
    }

    /**
     * @return list<class-string<ResponseFactoryInterface>>
     */
    private static function factoryClasses(): array
    {
        return [
            \Nyholm\Psr7\Factory\Psr17Factory::class,
            \GuzzleHttp\Psr7\HttpFactory::class,
            \Http\Factory\Guzzle\ResponseFactory::class,
            \Laminas\Diactoros\ResponseFactory::class,
            \Slim\Psr7\Factory\ResponseFactory::class,
        ];
    }
}
