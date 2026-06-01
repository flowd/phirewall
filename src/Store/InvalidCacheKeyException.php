<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

use Psr\SimpleCache\InvalidArgumentException;

/**
 * Thrown by the cache backends when a key does not satisfy the PSR-16 key rules.
 *
 * Implements {@see InvalidArgumentException} so that callers can catch the PSR-16
 * marker interface regardless of the concrete backend that raised it.
 */
final class InvalidCacheKeyException extends \InvalidArgumentException implements InvalidArgumentException
{
}
