<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Minimal representation of a single OWASP CRS rule.
 * This is a pragmatic subset that supports common patterns (REQUEST_URI + @rx) and a few additional operators/variables.
 */
final readonly class CoreRule
{
    private const PM_MAX_PHRASES = 5000;

    /**
     * @param list<string> $variables
     * @param array<string, int|string|bool> $actions
     */
    public function __construct(
        public int $id,
        public array $variables, // list of variable identifiers (e.g., ['REQUEST_URI'])
        public string $operator, // e.g., '@rx', '@contains'
        public string $operatorArgument, // e.g., pattern for @rx or needle for @contains
        public array $actions, // parsed action map (e.g., ['phase' => '2', 'deny' => true, 'msg' => '...'])
        public ?string $contextFolder = null, // folder path for context (e.g., for @pmFromFile)
    ) {
    }

    public function matches(ServerRequestInterface $serverRequest): bool
    {
        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return false;
        }

        $values = $this->collectVariableValues($serverRequest);
        if ($values === []) {
            return false;
        }

        return $this->evaluateOperator($values);
    }

    /**
     * Collect target values for all variables supported by this adapter.
     * Supported variables: REQUEST_URI, ARGS, REQUEST_HEADERS, REQUEST_HEADERS_NAMES, REQUEST_METHOD
     * (subset sufficient to exercise typical CRS checks).
     *
     * @return list<string>
     */
    private function collectVariableValues(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];
        foreach ($this->variables as $variable) {
            switch ($variable) {
                case 'REQUEST_URI':
                    $collected[] = $serverRequest->getUri()->getPath() . ($serverRequest->getUri()->getQuery() !== '' ? '?' . $serverRequest->getUri()->getQuery() : '');
                    break;
                case 'REQUEST_METHOD':
                    $collected[] = $serverRequest->getMethod();
                    break;
                case 'QUERY_STRING':
                    $collected[] = $serverRequest->getUri()->getQuery();
                    break;
                case 'ARGS':
                    $queryParams = $serverRequest->getQueryParams();
                    foreach ($queryParams as $k => $v) {
                        if (is_array($v)) {
                            foreach ($v as $vv) {
                                if (is_scalar($vv))  {
                                    $collected[] = (string)$vv;
                                }
                            }
                        } else {
                            if (is_scalar($v)) {
                                $collected[] = (string)$v;
                            }
                        }

                        $collected[] = (string)$k; // include argument names for name-based checks
                    }

                    $parsed = $serverRequest->getParsedBody();
                    if (is_array($parsed)) {
                        foreach ($parsed as $k => $v) {
                            if (is_array($v)) {
                                foreach ($v as $vv) {
                                    if (is_scalar($vv))  {
                                        $collected[] = (string)$vv;
                                    }
                                }
                            } else {
                                $collected[] = (string)$v;
                            }

                            $collected[] = (string)$k;
                        }
                    }

                    break;
                case 'ARGS_NAMES':
                    $queryParams = $serverRequest->getQueryParams();
                    foreach (array_keys($queryParams) as $k) {
                        $collected[] = (string)$k;
                    }

                    $parsed = $serverRequest->getParsedBody();
                    if (is_array($parsed)) {
                        foreach (array_keys($parsed) as $k) {
                            $collected[] = (string)$k;
                        }
                    }

                    break;
                case 'REQUEST_COOKIES':
                    foreach ($serverRequest->getCookieParams() as $v) {
                        $collected[] = (string)$v;
                    }

                    break;
                case 'REQUEST_COOKIES_NAMES':
                    foreach (array_keys($serverRequest->getCookieParams()) as $k) {
                        $collected[] = (string)$k;
                    }

                    break;
                case 'REQUEST_HEADERS':
                    foreach ($serverRequest->getHeaders() as $values) {
                        foreach ($values as $value) {
                            $collected[] = (string)$value;
                        }
                    }

                    break;
                case 'REQUEST_HEADERS_NAMES':
                    foreach (array_keys($serverRequest->getHeaders()) as $name) {
                        $collected[] = (string)$name;
                    }

                    break;
                case 'REQUEST_FILENAME':
                    // Basename of the request path (no query string)
                    $path = $serverRequest->getUri()->getPath();
                    if ($path !== '') {
                        $collected[] = basename($path);
                    }

                    break;
                default:
                    // unsupported variable: ignore
                    break;
            }
        }

        return array_values(array_filter($collected, fn(string $item): bool => $item !== ''));
    }

    /**
     * Evaluate operator against a list of values.
     * Currently supports:
     *  - @rx (PCRE),
     *  - @contains (case-insensitive substring),
     *  - @streq (case-insensitive equality)
     *
     * @param list<string> $values
     */
    private function evaluateOperator(array $values): bool
    {
        $op = strtolower($this->operator);
        switch ($op) {
            case '@rx':
                $pattern = $this->operatorArgument;
                // Ensure delimiters exist; if not provided, wrap with '~'
                $delimited = $this->ensureRegexDelimiters($pattern);
                foreach ($values as $value) {
                    if (@preg_match($delimited, $value) === 1) {
                        return true;
                    }
                }

                return false;
            case '@contains':
                $needle = $this->operatorArgument;
                if ($needle === '') {
                    return false;
                }

                foreach ($values as $value) {
                    if (stripos((string) $value, $needle) !== false) {
                        return true;
                    }
                }

                return false;
            case '@streq':
                $expected = $this->operatorArgument;
                foreach ($values as $value) {
                    if (strcasecmp((string) $value, $expected) === 0) {
                        return true;
                    }
                }

                return false;
            case '@startswith':
            case '@beginswith':
                $prefix = $this->operatorArgument;
                if ($prefix === '') {
                    return false;
                }

                $prefixLen = strlen($prefix);
                foreach ($values as $value) {
                    if (strncasecmp((string) $value, $prefix, $prefixLen) === 0) {
                        return true;
                    }
                }

                return false;
            case '@endswith':
                $suffix = $this->operatorArgument;
                if ($suffix === '') {
                    return false;
                }

                $slen = strlen($suffix);
                foreach ($values as $value) {
                    if ($slen === 0) {
                        continue;
                    }

                    if (strcasecmp(substr($value, -$slen), $suffix) === 0) {
                        return true;
                    }
                }

                return false;
            case '@pm':
                $phrases = $this->parsePhraseList($this->operatorArgument);
                if ($phrases === []) {
                    return false;
                }

                foreach ($values as $value) {
                    foreach ($phrases as $phrase) {
                        if ($phrase !== '' && stripos((string)$value, $phrase) !== false) {
                            return true;
                        }
                    }
                }

                return false;
            case '@pmfromfile':
                $phrases = $this->loadPmFromFilePhrases($this->operatorArgument);
                if ($phrases === []) {
                    return false;
                }

                foreach ($values as $value) {
                    foreach ($phrases as $phrase) {
                        if ($phrase !== '' && stripos((string)$value, $phrase) !== false) {
                            return true;
                        }
                    }
                }

                return false;
            default:
                // Unsupported operators are considered non-matching in this adapter.
                return false;
        }
    }

    /**
     * Parse a phrase list used by @pm operator. Supports quotes (single/double) and backslash escapes.
     * Separators: whitespace and commas.
     * @return list<string>
     */
    private function parsePhraseList(string $list): array
    {
        $tokens = [];
        $buf = '';
        $inQuote = false;
        $quote = '';
        $len = strlen($list);
        for ($i = 0; $i < $len; ++$i) {
            $ch = $list[$i];
            if ($inQuote) {
                if ($ch === '\\' && $i + 1 < $len) {
                    $buf .= $list[$i + 1];
                    ++$i;
                    continue;
                }

                if ($ch === $quote) {
                    $inQuote = false;
                    continue;
                }

                $buf .= $ch;
                continue;
            }

            if ($ch === "'" || $ch === '"') {
                $inQuote = true;
                $quote = $ch;
                continue;
            }

            if ($ch === ',' || ctype_space($ch)) {
                if ($buf !== '') {
                    $tokens[] = $buf;
                    $buf = '';
                }

                continue;
            }

            $buf .= $ch;
        }

        if ($buf !== '') {
            $tokens[] = $buf;
        }

        // Remove empties and duplicates while preserving order
        $out = [];
        $seen = [];
        foreach ($tokens as $token) {
            $token = trim($token);
            if ($token === '') {
                continue;
            }

            if (!isset($seen[$token])) {
                $seen[$token] = true;
                $out[] = $token;
                if (count($out) >= self::PM_MAX_PHRASES) {
                    break;
                }
            }
        }

        return $out;
    }

    private function ensureRegexDelimiters(string $pattern): string
    {
        // If pattern starts with a delimiter char and has a closing one, keep it.
        // Otherwise, wrap in '~' and escape unescaped '~'.
        if ($pattern !== '' && preg_match('/^(.)(.*)\1[imsxuADSUXJ]*$/', $pattern) === 1) {
            return $pattern;
        }

        $escaped = str_replace('~', '\~', $pattern);
        // Use Unicode mode by default to better mirror CRS behavior for text processing
        return '~' . $escaped . '~u';
    }

    /**
     * Load phrases from a file for @pmFromFile and return them lowercased.
     * Safety: missing/unreadable file returns empty list. Results are cached per path.
     * @return list<string>
     */
    /**
     * Load phrases from a file for @pmFromFile. Returns original (non-lowered) phrases; matching uses stripos().
     * Safety: missing/unreadable file returns empty list. Results are cached per path.
     * @return list<string>
     */
    private function loadPmFromFilePhrases(string $filePath): array
    {
        $path = $filePath;
        if ($this->contextFolder !== null) {
            $path = rtrim($this->contextFolder, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR .
                ltrim($filePath, DIRECTORY_SEPARATOR);
        }

        static $cache = [];
        if (isset($cache[$path])) {
            return $cache[$path];
        }

        if ($path === '' || !is_file($path)) {
            $cache[$path] = [];
            return [];
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            $cache[$path] = [];
            return [];
        }

        $lines = preg_split('/\r?\n/', $content) ?: [];
        $phrases = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, '#')) {
                continue;
            }

            // Allow comma/whitespace separated tokens per line using existing parser
            foreach ($this->parsePhraseList($line) as $token) {
                $token = trim($token);
                if (!in_array($token, $phrases, true)) {
                    $phrases[] = $token;
                }

                if (count($phrases) >= self::PM_MAX_PHRASES) {
                    break 2;
                }
            }
        }

        $cache[$path] = $phrases;
        return $phrases;
    }
}
