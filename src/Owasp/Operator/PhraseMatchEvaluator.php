<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Owasp\Operator;

/**
 * Evaluates values against a list of phrases using case-insensitive substring matching (@pm operator).
 */
final readonly class PhraseMatchEvaluator implements OperatorEvaluatorInterface
{
    /** @var list<string> Cached parsed phrase list. */
    private array $phrases;

    public function __construct(string $phraseList)
    {
        $this->phrases = PhraseListParser::parse($phraseList);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        if ($this->phrases === []) {
            return false;
        }

        foreach ($values as $value) {
            foreach ($this->phrases as $phrase) {
                if ($phrase !== '' && stripos($value, $phrase) !== false) {
                    return true;
                }
            }
        }

        return false;
    }
}
