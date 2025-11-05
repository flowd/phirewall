<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

final class FirewallResult
{
    public const OUTCOME_PASS = 'pass';
    public const OUTCOME_SAFELISTED = 'safelisted';
    public const OUTCOME_BLOCKED = 'blocked';
    public const OUTCOME_THROTTLED = 'throttled';

    /** @param array<string,string> $headers */
    private function __construct(
        public readonly string $outcome,
        public readonly ?string $rule,
        public readonly ?string $blockType,
        public readonly ?int $retryAfter,
        public readonly array $headers,
    ) {
    }

    /**
     * Generic pass-through (no special headers).
     * @param array<string,string> $headers
     */
    public static function pass(array $headers = []): self
    {
        return new self(self::OUTCOME_PASS, null, null, null, $headers);
    }

    /**
     * Safelisted pass-through with header.
     * @param array<string,string> $headers
     */
    public static function safelisted(string $rule, array $headers = []): self
    {
        return new self(self::OUTCOME_SAFELISTED, $rule, null, null, $headers);
    }

    /**
     * Blocked (403), type is 'blocklist' or 'fail2ban'
     * @param array<string,string> $headers
     */
    public static function blocked(string $rule, string $type, array $headers = []): self
    {
        return new self(self::OUTCOME_BLOCKED, $rule, $type, null, $headers);
    }

    /**
     * Throttled (429)
     * @param array<string,string> $headers
     */
    public static function throttled(string $rule, int $retryAfter, array $headers = []): self
    {
        return new self(self::OUTCOME_THROTTLED, $rule, 'throttle', $retryAfter, $headers);
    }

    public function isPass(): bool
    {
        return $this->outcome === self::OUTCOME_PASS || $this->outcome === self::OUTCOME_SAFELISTED;
    }

    public function isBlocked(): bool
    {
        return $this->outcome === self::OUTCOME_BLOCKED || $this->outcome === self::OUTCOME_THROTTLED;
    }
}
