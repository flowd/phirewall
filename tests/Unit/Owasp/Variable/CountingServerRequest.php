<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp\Variable;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/**
 * Test double that decorates a PSR-7 request and counts how often the request-data
 * accessors are read, so tests can assert that the per-request memo derives each
 * variable only once across many rules.
 *
 * This double is read-only: the PSR-7 with*()/without*() mutators are unsupported and
 * throw instead of returning $this (which would silently violate immutability and mask
 * bugs if a future test mutated the request through the wrapper).
 */
final class CountingServerRequest implements ServerRequestInterface
{
    public int $queryParamReads = 0;

    public int $parsedBodyReads = 0;

    public function __construct(
        private readonly ServerRequestInterface $inner,
    ) {
    }

    /** @return array<array-key, mixed> */
    public function getQueryParams(): array
    {
        ++$this->queryParamReads;

        return $this->inner->getQueryParams();
    }

    /** @return array<array-key, mixed>|object|null */
    public function getParsedBody()
    {
        ++$this->parsedBodyReads;

        return $this->inner->getParsedBody();
    }

    public function getProtocolVersion(): string
    {
        return $this->inner->getProtocolVersion();
    }

    public function withProtocolVersion(string $version): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @return array<string, array<int, string>> */
    public function getHeaders(): array
    {
        return $this->inner->getHeaders();
    }

    public function hasHeader(string $name): bool
    {
        return $this->inner->hasHeader($name);
    }

    /** @return array<int, string> */
    public function getHeader(string $name): array
    {
        return $this->inner->getHeader($name);
    }

    public function getHeaderLine(string $name): string
    {
        return $this->inner->getHeaderLine($name);
    }

    public function withHeader(string $name, $value): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function withAddedHeader(string $name, $value): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function withoutHeader(string $name): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function getBody(): StreamInterface
    {
        return $this->inner->getBody();
    }

    public function withBody(StreamInterface $stream): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function getRequestTarget(): string
    {
        return $this->inner->getRequestTarget();
    }

    public function withRequestTarget(string $requestTarget): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function getMethod(): string
    {
        return $this->inner->getMethod();
    }

    public function withMethod(string $method): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function getUri(): UriInterface
    {
        return $this->inner->getUri();
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @return array<array-key, mixed> */
    public function getServerParams(): array
    {
        return $this->inner->getServerParams();
    }

    /** @return array<array-key, mixed> */
    public function getCookieParams(): array
    {
        return $this->inner->getCookieParams();
    }

    /** @param array<array-key, mixed> $cookies */
    public function withCookieParams(array $cookies): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @param array<array-key, mixed> $query */
    public function withQueryParams(array $query): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @return array<array-key, mixed> */
    public function getUploadedFiles(): array
    {
        return $this->inner->getUploadedFiles();
    }

    /** @param array<array-key, mixed> $uploadedFiles */
    public function withUploadedFiles(array $uploadedFiles): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @param array<array-key, mixed>|object|null $data */
    public function withParsedBody($data): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    /** @return array<array-key, mixed> */
    public function getAttributes(): array
    {
        return $this->inner->getAttributes();
    }

    public function getAttribute(string $name, $default = null): mixed
    {
        return $this->inner->getAttribute($name, $default);
    }

    public function withAttribute(string $name, $value): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    public function withoutAttribute(string $name): static
    {
        $this->mutationUnsupported(__FUNCTION__);
    }

    private function mutationUnsupported(string $method): never
    {
        throw new \BadMethodCallException(sprintf(
            '%s is a read-only counting test double; %s() is not supported.',
            self::class,
            $method,
        ));
    }
}
