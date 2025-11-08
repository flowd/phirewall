<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts a stable key from the request or returns null to skip.
 */
interface KeyExtractorInterface
{
    public function extract(ServerRequestInterface $serverRequest): ?string;
}
