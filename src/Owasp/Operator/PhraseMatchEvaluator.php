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
        return self::matchAny($values, $this->phrases);
    }

    /**
     * Check if any value contains any phrase (case-insensitive).
     *
     * Shared by PhraseMatchEvaluator and PhraseMatchFromFileEvaluator.
     *
     * @param list<string> $values
     * @param list<string> $phrases
     */
    public static function matchAny(array $values, array $phrases): bool
    {
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
}
