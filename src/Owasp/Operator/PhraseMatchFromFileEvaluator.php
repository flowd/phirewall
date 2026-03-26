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
        $phrases = $this->loadPhrases();
        if ($phrases === []) {
            return false;
        }

        foreach ($values as $value) {
            foreach ($phrases as $phrase) {
                if ($phrase !== '' && stripos($value, $phrase) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Load phrases from the configured file path.
     * Safety: missing/unreadable file returns empty list. Results are cached per resolved path.
     *
     * @return list<string>
     */
    private function loadPhrases(): array
    {
        $path = $this->filePath;
        if ($this->contextFolder !== null) {
            $path = rtrim($this->contextFolder, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR .
                ltrim($this->filePath, DIRECTORY_SEPARATOR);
        }

        if (str_contains($this->filePath, '..')) {
            throw new \RuntimeException("Path traversal detected in @pmFromFile: {$this->filePath}");
        }

        /** @var array<string, list<string>> $cache */
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
