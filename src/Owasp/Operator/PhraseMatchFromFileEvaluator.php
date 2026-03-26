<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values against phrases loaded from a file (@pmFromFile operator).
 * Supports path traversal prevention and per-path caching.
 */
final readonly class PhraseMatchFromFileEvaluator implements OperatorEvaluatorInterface
{
    public function __construct(
        private string $filePath,
        private ?string $contextFolder = null,
    ) {
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return PhraseMatchEvaluator::matchAny($values, $this->loadPhrases());
    }

    /**
     * Load phrases from the configured file path.
     * Safety: missing/unreadable file returns empty list. Results are cached per resolved path.
     *
     * @return list<string>
     */
    private function loadPhrases(): array
    {
        // Check for directory traversal components (/../ or leading ../) before
        // constructing the resolved path. Uses a regex to avoid false positives on
        // legitimate filenames containing '..' (e.g., 'my..config.txt').
        if (preg_match('#(?:^|[\\\\/])\.\.(?:[\\\\/]|$)#', $this->filePath) === 1) {
            throw new \RuntimeException('Path traversal detected in @pmFromFile operand.');
        }

        $path = $this->filePath;
        if ($this->contextFolder !== null) {
            $path = rtrim($this->contextFolder, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR .
                ltrim($this->filePath, DIRECTORY_SEPARATOR);
        }

        /** @var array<string, list<string>> $cache */
        static $cache = [];
        if (isset($cache[$path])) {
            return $cache[$path];
        }

        // Evict oldest entry when cache exceeds limit to prevent unbounded
        // growth in long-running processes.
        if (count($cache) >= 256) {
            array_shift($cache);
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

            // Allow comma/whitespace separated tokens per line using shared parser
            foreach (PhraseListParser::parse($line) as $token) {
                $token = trim($token);
                if (!in_array($token, $phrases, true)) {
                    $phrases[] = $token;
                }

                if (count($phrases) >= PhraseListParser::MAX_PHRASES) {
                    break 2;
                }
            }
        }

        $cache[$path] = $phrases;
        return $phrases;
    }
}
