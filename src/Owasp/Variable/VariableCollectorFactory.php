<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

/**
 * Factory that resolves OWASP CRS variable names to their corresponding collector instances.
 */
final class VariableCollectorFactory
{
    /**
     * Resolve a single variable name to its collector, or null when the variable is unsupported.
     */
    public static function create(string $variableName): ?VariableCollectorInterface
    {
        return match ($variableName) {
            'REQUEST_URI' => new RequestUriCollector(),
            'REQUEST_METHOD' => new RequestMethodCollector(),
            'QUERY_STRING' => new QueryStringCollector(),
            'ARGS' => new ArgsCollector(),
            'ARGS_NAMES' => new ArgsNamesCollector(),
            'REQUEST_COOKIES' => new RequestCookiesCollector(),
            'REQUEST_COOKIES_NAMES' => new RequestCookiesNamesCollector(),
            'REQUEST_HEADERS' => new RequestHeadersCollector(),
            'REQUEST_HEADERS_NAMES' => new RequestHeadersNamesCollector(),
            'REQUEST_FILENAME' => new RequestFilenameCollector(),
            default => null,
        };
    }
}
