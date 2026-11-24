<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

/**
 * A request path in both its raw (percent-encoded, as PSR-7 reports it) and
 * its normalised form, produced by {@see PathNormalizer::analyze()}.
 *
 * `ambiguous` is true when the raw path contains a construct that web servers
 * and routers resolve differently (dot-segments, an encoded slash, a
 * backslash, duplicate slashes, control characters, bytes that are not valid
 * UTF-8, or a path that does not start with `/`). For such a path the
 * normalised form is the firewall's best guess, not necessarily the resource
 * the application serves, so rules that GRANT something (safelists) must not
 * match it. See the {@see PathNormalizer} docblock for the full reasoning.
 */
final readonly class NormalizedPath
{
    public function __construct(
        public string $raw,
        public string $normalized,
        public bool $ambiguous,
    ) {
    }
}
