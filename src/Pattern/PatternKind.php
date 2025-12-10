<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

final class PatternKind
{
    public const IP = 'ip';

    public const CIDR = 'cidr';

    public const PATH_EXACT = 'path_exact';

    public const PATH_PREFIX = 'path_prefix';

    public const PATH_REGEX = 'path_regex';

    public const HEADER_EXACT = 'header_exact';

    public const HEADER_REGEX = 'header_regex';

    public const REQUEST_REGEX = 'request_regex';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::IP,
            self::CIDR,
            self::PATH_EXACT,
            self::PATH_PREFIX,
            self::PATH_REGEX,
            self::HEADER_EXACT,
            self::HEADER_REGEX,
            self::REQUEST_REGEX,
        ];
    }
}
