<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

/**
 * Very small SecRule parser to support a pragmatic subset of CRS.
 *
 * The set of supported variables is defined by {@see \Flowd\Phirewall\Owasp\Variable\VariableCollectorFactory}
 * and the set of supported operators by {@see \Flowd\Phirewall\Owasp\Operator\OperatorEvaluatorFactory};
 * those factories are the source of truth. Actions: id (required), phase (ignored),
 * deny/block (boolean), msg (optional).
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
     * Quoted segments act as the delimiters; unquoted runs between them form their own segments.
     *
     * @return list<string>
     */
    private function splitTopLevel(string $line): array
    {
        $segments = [];
        foreach ($this->scanSpans($line) as $span) {
            if ($span['quoted']) {
                // A quoted span is its own segment, surrounding quotes retained.
                $segments[] = $span['text'];
                continue;
            }

            // Unquoted runs are emitted as-is (trimmed) when they carry content.
            $trimmed = trim($span['text']);
            if ($trimmed !== '') {
                $segments[] = $trimmed;
            }
        }

        return $segments;
    }

    /**
     * Walk a string honoring quote state (single or double) and backslash-escapes inside quotes,
     * yielding alternating unquoted and quoted spans. Quoted spans retain their surrounding quote
     * characters and any escape sequences verbatim, exactly as the source text contained them.
     *
     * This is the single low-level scanner shared by {@see splitTopLevel()} and {@see parseActions()};
     * each method applies its own emission rules on top of the produced spans.
     *
     * @return list<array{quoted: bool, text: string}>
     */
    private function scanSpans(string $input): array
    {
        $spans = [];
        $current = '';
        $inQuote = false;
        $quoteChar = '';
        $length = strlen($input);
        for ($index = 0; $index < $length; ++$index) {
            $character = $input[$index];
            if ($inQuote) {
                if ($character === '\\' && $index + 1 < $length) { // escape: keep both characters
                    $current .= $character . $input[$index + 1];
                    ++$index;
                    continue;
                }

                if ($character === $quoteChar) {
                    $inQuote = false;
                    $current .= $character;
                    $spans[] = ['quoted' => true, 'text' => $current];
                    $current = '';
                    continue;
                }

                $current .= $character;
                continue;
            }

            if ($character === '"' || $character === "'") {
                if ($current !== '') {
                    $spans[] = ['quoted' => false, 'text' => $current];
                }

                $current = $character;
                $inQuote = true;
                $quoteChar = $character;
                continue;
            }

            $current .= $character;
        }

        if ($current !== '') {
            // A still-open quote is treated as an unterminated unquoted run, matching prior behavior.
            $spans[] = ['quoted' => false, 'text' => $current];
        }

        return $spans;
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

        // @rx arguments are bare PCRE content per ModSecurity grammar — there is no
        // second quoting layer to strip. Stripping surrounding quotes here corrupts
        // patterns whose first and last bytes are literal quote characters (e.g. CRS
        // rule 942511 wraps its alternation in literal apostrophes), collapsing the
        // regex to its inner body and matching essentially every HTTP value. The outer
        // SecRule-level quoting has already been removed by stripQuotes($parts[1]) in
        // parseLine, so the remaining content is the pattern verbatim.
        if (strtolower($op) === '@rx') {
            return [$op, ltrim($arg)];
        }

        // Remove surrounding quotes if present
        $arg = $this->stripQuotes(trim($arg));
        $arg = trim($this->unescape($arg));

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
        $buffer = '';
        $parts = [];
        foreach ($this->scanSpans($actionsPart) as $span) {
            if ($span['quoted']) {
                // Quoted spans (including any commas within) never split a part.
                $buffer .= $span['text'];
                continue;
            }

            // Unquoted runs split into parts on top-level commas.
            $fragments = explode(',', $span['text']);
            $lastIndex = count($fragments) - 1;
            foreach ($fragments as $fragmentIndex => $fragment) {
                $buffer .= $fragment;
                if ($fragmentIndex !== $lastIndex) {
                    $parts[] = trim($buffer);
                    $buffer = '';
                }
            }
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
