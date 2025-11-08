<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Config\Rule;

interface RuleInterface
{
    public function name(): string;
}
