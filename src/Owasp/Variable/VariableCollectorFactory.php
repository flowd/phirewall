<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Variable;

/**
 * Factory that resolves OWASP CRS variable names to their corresponding collector instances.
 */
final class VariableCollectorFactory
{
    /**
     * Resolve a list of variable names to their corresponding collectors.
     * Unknown variable names are silently skipped.
     *
     * @param list<string> $variableNames
     * @return list<VariableCollectorInterface>
     */
    public static function createCollectors(array $variableNames): array
    {
        $collectors = [];
        foreach ($variableNames as $variableName) {
            $collector = self::create($variableName);
            if ($collector instanceof VariableCollectorInterface) {
                $collectors[] = $collector;
            }
        }

        return $collectors;
    }

    private static function create(string $variableName): ?VariableCollectorInterface
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
