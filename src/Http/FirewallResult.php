<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

final readonly class FirewallResult
{
    /** @param array<string,string> $headers */
    private function __construct(
        public Outcome $outcome,
        public ?string $rule,
        public ?string $blockType,
        public ?int $retryAfter,
        public array $headers,
    ) {
    }

    /**
     * Generic pass-through (no special headers).
     * @param array<string,string> $headers
     */
    public static function pass(array $headers = []): self
    {
        return new self(Outcome::PASS, null, null, null, $headers);
    }

    /**
     * Safelisted pass-through with header.
     * @param array<string,string> $headers
     */
    public static function safelisted(string $rule, array $headers = []): self
    {
        return new self(Outcome::SAFELISTED, $rule, null, null, $headers);
    }

    /**
     * Blocked (403), type is 'blocklist' or 'fail2ban'
     * @param array<string,string> $headers
     */
    public static function blocked(string $rule, string $type, array $headers = []): self
    {
        return new self(Outcome::BLOCKED, $rule, $type, null, $headers);
    }

    /**
     * Throttled (429)
     * @param array<string,string> $headers
     */
    public static function throttled(string $rule, int $retryAfter, array $headers = []): self
    {
        return new self(Outcome::THROTTLED, $rule, 'throttle', $retryAfter, $headers);
    }

    public function isPass(): bool
    {
        return $this->outcome === Outcome::PASS || $this->outcome === Outcome::SAFELISTED;
    }

    public function isBlocked(): bool
    {
        return $this->outcome === Outcome::BLOCKED || $this->outcome === Outcome::THROTTLED;
    }
}
