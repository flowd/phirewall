<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

/**
 * Very small SecRule parser to support a pragmatic subset of CRS:
 * - Variables: REQUEST_URI, ARGS, REQUEST_HEADERS, REQUEST_HEADERS_NAMES
 * - Operator: @rx with argument (PCRE)
 * - Actions: id (required), phase (ignored), deny (boolean), msg (optional)
 */
final class SecRuleParser
{
    /**
     * Parse a raw CRS "SecRule" line into a CoreRule, or null if unsupported.
     */
    public function parseLine(string $line, ?string $contextFolder = null): ?CoreRule
    {
        // Defensive: collapse backslash-newline continuations into a single logical line
        // Join "\\\n<indent>" and "\\\r\n<indent>" sequences
        $line = preg_replace("/\\\\\r?\n[ \t]*/", '', $line) ?? $line;

        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            return null;
        }

        if (!str_starts_with($line, 'SecRule ')) {
            return null;
        }

        // Basic pattern: SecRule <VARIABLES> "<OP> <ARG>" "<ACTIONS>"
        // We will extract quoted segments first.
        $parts = $this->splitTopLevel($line);
        if (count($parts) < 3) {
            return null;
        }

        // parts[0] is the full command; remove leading 'SecRule '
        $variablesPart = trim(substr($parts[0], strlen('SecRule ')));
        $operatorPart = $this->stripQuotes($parts[1]);
        $actionsPart = $this->stripQuotes($parts[2]);

        // Variables split by | (handle transforms by ignoring
        $variables = array_values(array_filter(array_map('trim', explode('|', $variablesPart)), static fn($v): bool => $v !== ''));
        if ($variables === []) {
            return null;
        }

        // Operator e.g.: @rx somepattern
        [$op, $arg] = $this->parseOperator($operatorPart);
        if ($op === null || $arg === null) {
            return null;
        }

        // Actions: comma-separated key[:value]
        $actions = $this->parseActions($actionsPart);
        $id = isset($actions['id']) ? (int)$actions['id'] : 0;
        if ($id <= 0) {
            return null; // require id
        }

        // Map block to deny for compatibility with CRS syntax
        $hasDeny = array_key_exists('deny', $actions) ? (bool)$actions['deny'] : str_contains($actionsPart, 'deny');
        $hasBlock = array_key_exists('block', $actions) ? (bool)$actions['block'] : str_contains($actionsPart, 'block');
        $actions['deny'] = $hasDeny || $hasBlock;

        return new CoreRule($id, $variables, $op, $arg, $actions, $contextFolder);
    }

    /**
     * Split a SecRule line into parts: ["SecRule <vars>", "<op arg>", "<actions>"]
     * We find quoted segments while respecting escaped quotes.
     *
     * @return list<string>
     */
    private function splitTopLevel(string $line): array
    {
        $segments = [];
        $current = '';
        $inQuote = false;
        $quoteChar = '';
        $len = strlen($line);
        for ($i = 0; $i < $len; ++$i) {
            $ch = $line[$i];
            if ($inQuote) {
                if ($ch === '\\' && $i + 1 < $len) { // escape
                    $current .= $ch . $line[$i + 1];
                    ++$i;
                    continue;
                }

                if ($ch === $quoteChar) {
                    $inQuote = false;
                    $current .= $ch;
                    $segments[] = $current;
                    $current = '';
                    continue;
                }

                $current .= $ch;
                continue;
            }

            if ($ch === '"' || $ch === "'") {
                // push current non-quoted chunk if non-empty
                if (trim($current) !== '') {
                    $segments[] = trim($current);
                }

                $current = $ch;
                $inQuote = true;
                $quoteChar = $ch;
                continue;
            }

            $current .= $ch;
        }

        if (trim($current) !== '') {
            $segments[] = trim($current);
        }

        return $segments;
    }

    /**
     * @return array{0:?string,1:?string}
     */
    private function parseOperator(string $operatorPart): array
    {
        $operatorPart = trim($operatorPart);
        if ($operatorPart === '') {
            return [null, null];
        }

        // First token is operator, rest is argument (may contain spaces)
        $spacePos = strpos($operatorPart, ' ');
        if ($spacePos === false) {
            return [null, null];
        }

        $op = trim(substr($operatorPart, 0, $spacePos));
        $arg = substr($operatorPart, $spacePos + 1);
        // Remove surrounding quotes if present
        $arg = $this->stripQuotes(trim($arg));
        // For @rx keep escapes but trim leading/trailing whitespace that may precede the pattern inside quotes
        $arg = strtolower($op) === '@rx' ? ltrim($arg) : trim($this->unescape($arg));

        return [$op, $arg];
    }

    private function unescape(string $value): string
    {
        // For non-regex operators, unescape simple sequences to present clean arguments
        // (e.g., convert \" to ", \\' to ', and \\\\ to \\).
        return str_replace(['\\"', "\\'", '\\\\'], ['"', "'", '\\'], $value);
    }

    /**
     * Parse actions key/value map. Values can be quoted (single or double). Commas separate actions.
     * Boolean actions like "deny" will be set to true.
     * @return array<string, int|string|bool>
     */
    private function parseActions(string $actionsPart): array
    {
        $actions = [];
        $cursor = 0;
        $len = strlen($actionsPart);
        $buffer = '';
        $inQuote = false;
        $quote = '';
        $parts = [];
        while ($cursor < $len) {
            $ch = $actionsPart[$cursor];
            if ($inQuote) {
                if ($ch === '\\' && $cursor + 1 < $len) {
                    $buffer .= $ch . $actionsPart[$cursor + 1];
                    $cursor += 2;
                    continue;
                }

                if ($ch === $quote) {
                    $inQuote = false;
                    $buffer .= $ch;
                    ++$cursor;
                    continue;
                }

                $buffer .= $ch;
                ++$cursor;
                continue;
            }

            if ($ch === '"' || $ch === "'") {
                $inQuote = true;
                $quote = $ch;
                $buffer .= $ch;
                ++$cursor;
                continue;
            }

            if ($ch === ',') {
                $parts[] = trim($buffer);
                $buffer = '';
                ++$cursor;
                continue;
            }

            $buffer .= $ch;
            ++$cursor;
        }

        if (trim($buffer) !== '') {
            $parts[] = trim($buffer);
        }

        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            $kv = explode(':', $part, 2);
            if (count($kv) === 1) {
                $actions[$kv[0]] = true;
            } else {
                $key = trim($kv[0]);
                $value = $this->stripQuotes(trim($kv[1]));
                $actions[$key] = is_numeric($value) ? (int)$value : $value;
            }
        }

        return $actions;
    }

    private function stripQuotes(string $value): string
    {
        $l = strlen($value);
        if ($l >= 2 && (($value[0] === '"' && $value[$l - 1] === '"') || ($value[0] === "'" && $value[$l - 1] === "'"))) {
            return substr($value, 1, -1);
        }

        return $value;
    }
}
