<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Store;

/**
 * The character rules shared by cache-key validation ({@see KeyValidationTrait})
 * and key-prefix validation ({@see \Flowd\Phirewall\Config}), kept in one place
 * so the reserved set and the control/whitespace rule cannot drift apart between
 * the two call sites.
 */
final class CacheKeyRules
{
    /**
     * PSR-16 reserved characters (including the backslash) that MUST NOT appear
     * in a cache key. Control and whitespace characters are additionally
     * rejected by {@see firstIllegalCharacter()} as a Phirewall restriction of
     * its own (not mandated by PSR-16).
     */
    public const RESERVED_CHARACTERS = '{}()/\\@:';

    /**
     * Return the first character that makes $value an invalid cache key — a
     * PSR-16 reserved character or a control/whitespace character — or null when
     * the value is clean.
     *
     * @return array{character: string, reserved: bool}|null
     */
    public static function firstIllegalCharacter(string $value): ?array
    {
        $reserved = strpbrk($value, self::RESERVED_CHARACTERS);
        if ($reserved !== false) {
            return ['character' => $reserved[0], 'reserved' => true];
        }

        if (preg_match('/[\s\x00-\x1f\x7f]/', $value, $matches) === 1) {
            return ['character' => $matches[0], 'reserved' => false];
        }

        return null;
    }

    /**
     * Build a log-safe validation message for the given subject and offending
     * character. A reserved character is printable and shown verbatim; a control
     * or whitespace character is reported as an escaped hex code so its raw bytes
     * never reach a log (CWE-117). The raw subject value is deliberately never
     * embedded.
     *
     * @param array{character: string, reserved: bool} $illegalCharacter
     */
    public static function describeViolation(string $subject, array $illegalCharacter): string
    {
        if ($illegalCharacter['reserved']) {
            return sprintf(
                '%s contains the reserved character "%s"; the characters %s are not allowed.',
                $subject,
                $illegalCharacter['character'],
                self::RESERVED_CHARACTERS,
            );
        }

        return sprintf(
            '%s contains an illegal control or whitespace character (\\x%02x).',
            $subject,
            ord($illegalCharacter['character']),
        );
    }
}
