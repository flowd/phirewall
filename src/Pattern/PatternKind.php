<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

enum PatternKind: string
{
    case IP = 'ip';

    case CIDR = 'cidr';

    case PATH_EXACT = 'path_exact';

    case PATH_PREFIX = 'path_prefix';

    case PATH_REGEX = 'path_regex';

    case HEADER_EXACT = 'header_exact';

    case HEADER_REGEX = 'header_regex';

    case REQUEST_REGEX = 'request_regex';
}
