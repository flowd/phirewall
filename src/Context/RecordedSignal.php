<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Context;

use Flowd\Phirewall\BanType;

/**
 * Immutable value object representing a single post-handler signal recorded
 * by application code via the RequestContext.
 *
 * A signal carries the ban-type (fail2ban or allow2ban) and an optional key
 * override. When `$key` is null, the firewall extracts the discriminator
 * from the matching rule's keyExtractor on the same request — handlers do
 * not need to repeat the rule's keying logic.
 */
final readonly class RecordedSignal
{
    public function __construct(
        public string $ruleName,
        public BanType $banType,
        public ?string $key = null,
    ) {
    }
}
