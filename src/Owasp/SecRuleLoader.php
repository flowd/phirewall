<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp;

final class SecRuleLoader
{
    /**
     * Split text into logical SecRule lines, supporting backslash (\\) line continuations.
     * - Joins lines ending with an unquoted trailing backslash.
     * - Trims the trailing backslash and newline, and consumes indentation on the next line.
     * - Preserves content inside quotes (no continuation when inside quote).
     * - Skips empty lines and comment-only lines (starting with #, outside quotes).
     *
     * @return list<string>
     */
    private static function logicalLines(string $text): array
    {
        $len = strlen($text);
        $lines = [];
        $buf = '';
        $inQuote = false;
        $quote = '';
        for ($i = 0; $i < $len; ++$i) {
            $ch = $text[$i];

            if ($inQuote) {
                if ($ch === '\\' && $i + 1 < $len) {
                    // keep escapes as-is inside quoted segments
                    $buf .= $ch . $text[$i + 1];
                    ++$i;
                    continue;
                }

                if ($ch === $quote) {
                    $inQuote = false;
                    $quote = '';
                    $buf .= $ch;
                    continue;
                }

                $buf .= $ch;
                continue;
            }

            // Skip full comment lines starting with # (ignoring leading spaces/tabs)
            if ($ch === '#' && trim($buf) === '') {
                // consume until end of line
                while ($i + 1 < $len && $text[$i + 1] !== "\n") {
                    ++$i;
                }

                // reset buffer for this line (comment ignored)
                $buf = '';
                continue;
            }

            if ($ch === '"' || $ch === "'") {
                $inQuote = true;
                $quote = $ch;
                $buf .= $ch;
                continue;
            }

            if ($ch === "\r") {
                // normalize CRLF to handle at the LF
                continue;
            }

            if ($ch === "\n") {
                // Determine if previous non-space char is a backslash
                $j = strlen($buf) - 1;
                while ($j >= 0 && ($buf[$j] === ' ' || $buf[$j] === "\t")) {
                    --$j;
                }

                $isContinuation = ($j >= 0 && $buf[$j] === '\\');
                if ($isContinuation) {
                    // remove the trailing backslash and any spaces before it
                    $buf = rtrim(substr($buf, 0, $j), " \t");
                    // consume indentation on the following line
                    // skip subsequent spaces/tabs at the start of next line
                    $k = $i + 1;
                    while ($k < $len && ($text[$k] === ' ' || $text[$k] === "\t")) {
                        ++$k;
                    }

                    $i = $k - 1; // loop will ++ to next meaningful char
                    continue; // continue accumulating in same logical line
                }

                // finalize current logical line
                $trimmed = trim($buf);
                if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
                    $lines[] = $trimmed;
                }

                $buf = '';
                continue;
            }

            $buf .= $ch;
        }

        $trimmed = trim($buf);
        if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
            $lines[] = $trimmed;
        }

        return $lines;
    }

    public static function fromString(string $rulesText, ?string $contextFolder = null): CoreRuleSet
    {
        $secRuleParser = new SecRuleParser();
        $rules = [];
        $lines = self::logicalLines($rulesText);

        foreach ($lines as $line) {
            $rule = $secRuleParser->parseLine($line, $contextFolder);
            if ($rule instanceof CoreRule) {
                $rules[] = $rule;
            }
        }

        return new CoreRuleSet($rules);
    }

    /**
     * Returns a tuple: [rules => CoreRuleSet, parsed => int, skipped => int]
     * @return array{rules: CoreRuleSet, parsed: int, skipped: int}
     */
    public static function fromStringWithReport(string $rulesText): array
    {
        $secRuleParser = new SecRuleParser();
        $rules = [];
        $parsed = 0;
        $skipped = 0;
        $lines = self::logicalLines($rulesText);

        foreach ($lines as $line) {
            $rule = $secRuleParser->parseLine($line);
            if ($rule instanceof CoreRule) {
                $rules[] = $rule;
                ++$parsed;
            } else {
                ++$skipped;
            }
        }

        return [
            'rules' => new CoreRuleSet($rules),
            'parsed' => $parsed,
            'skipped' => $skipped,
        ];
    }

    public static function fromFile(string $filePath): CoreRuleSet
    {
        if (!is_file($filePath)) {
            throw new \InvalidArgumentException('Rules file not found: ' . $filePath);
        }

        $content = (string)file_get_contents($filePath);
        return self::fromString($content);
    }

    /**
     * Load and concatenate multiple files into a single CoreRuleSet.
     * Files that do not exist will trigger an exception.
     * @param list<string> $paths
     */
    public static function fromFiles(array $paths): CoreRuleSet
    {
        $buffer = '';
        $directoryOfFirstFile = null;
        foreach ($paths as $path) {
            $path = realpath($path);

            if ($path === false || !is_file($path)) {
                throw new \InvalidArgumentException('Rules file not found: ' . $path);
            }

            if ($directoryOfFirstFile === null) {
                $directoryOfFirstFile = dirname($path);
            } else {
                $currentDir = dirname($path);
                if ($currentDir !== $directoryOfFirstFile) {
                    throw new \InvalidArgumentException(sprintf("File '%s' of a CoreRuleSet must be in the same folder as other files ('%s').", $path, $directoryOfFirstFile));
                }
            }

            $buffer .= file_get_contents($path) . "\n";
        }

        return self::fromString($buffer, $directoryOfFirstFile);
    }

    /**
     * Load all files from a directory, optionally filtered. Files are processed in sorted order.
     * @param callable(string):bool|null $filter
     */
    public static function fromDirectory(string $dir, ?callable $filter = null): CoreRuleSet
    {
        // Ensure path is absolute
        $dir = realpath($dir);

        if ($dir === false || !is_dir($dir)) {
            throw new \InvalidArgumentException('Rules directory not found: ' . $dir);
        }

        $entries = scandir($dir);
        if ($entries === false) {
            $entries = [];
        }

        $files = [];
        foreach ($entries as $entry) {
            if ($entry === '.') {
                continue;
            }

            if ($entry === '..') {
                continue;
            }

            $path = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
            if (is_file($path) && ($filter === null || $filter($path) === true)) {
                $files[] = $path;
            }
        }

        sort($files, SORT_STRING);
        return self::fromFiles($files);
    }
}
