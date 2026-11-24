<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Infrastructure;

use InvalidArgumentException;
use RuntimeException;

/**
 * Apache .htaccess adapter for IP blocking.
 *
 * This adapter maintains a managed section in the .htaccess file delimited by markers:
 *   # BEGIN Phirewall
 *   # END Phirewall
 *
 * With at least one blocked address, the section holds a single mod_authz_core block
 * (Apache 2.4+, mod_authz_core plus ap_expr for <If>):
 *
 *   # BEGIN Phirewall
 *   <If "true">
 *       AuthMerging And
 *       <RequireAll>
 *           Require all granted
 *           Require not ip 203.0.113.250
 *       </RequireAll>
 *   </If>
 *   # END Phirewall
 *
 * Without blocked addresses, the section contains only the two markers. Content outside
 * the managed section is preserved.
 *
 * Why this shape:
 * - Apache rejects a negated "Require not ip" outside <RequireAll>/<RequireNone> with
 *   "negative Require directive has no effect in <RequireAny> directive" and answers every
 *   request in the directory with HTTP 500. Versions before this shape wrote bare
 *   "Require not ip" lines between the markers; such files are still read, and the next
 *   block/unblock call rewrites them into the form above.
 * - A bare top-level <RequireAll>Require all granted / Require not ip</RequireAll> is not
 *   safe either: top-level authorization directives of one .htaccess are merged into an
 *   implicit <RequireAny>, so it would sit next to the site's own directives (for example
 *   "Require valid-user") and grant every non-blocked client access without them. Because
 *   AuthMerging defaults to Off, it would also replace a restriction from the parent
 *   directory's configuration.
 * - The <If "true"> section is merged after the .htaccess, so it is its own authorization
 *   section, and "AuthMerging And" combines it with everything that applies before it
 *   (server config, parent directories, the site's own directives in this .htaccess) by
 *   logical AND. The block can therefore only deny: blocked addresses get 403, every other
 *   client is decided by the surrounding configuration exactly as without the block. The
 *   <If> section is also inherited by subdirectories and merged after their own .htaccess,
 *   so a subdirectory "Require all granted" does not lift the block.
 *
 * Known limitation: an <If>/<ElseIf>/<Else> section with its own Require directives that
 * Apache merges after this one - placed below the managed section in the same .htaccess, or
 * in a subdirectory's .htaccess - replaces the block for the requests it applies to, because
 * AuthMerging defaults to Off. Such a section needs "AuthMerging And" itself.
 * <If> in .htaccess works with "AllowOverride AuthConfig", the same override the previous
 * Require lines needed.
 */
final readonly class ApacheHtaccessAdapter implements InfrastructureBlockerInterface
{
    private const BEGIN_MARK = '# BEGIN Phirewall';

    private const END_MARK   = '# END Phirewall';

    /**
     * Wrapper lines around the "Require not ip" lines, see the class docblock.
     */
    private const BLOCK_OPEN = [
        '<If "true">',
        '    AuthMerging And',
        '    <RequireAll>',
        '        Require all granted',
    ];

    private const BLOCK_CLOSE = [
        '    </RequireAll>',
        '</If>',
    ];

    public function __construct(
        private string $htaccessPath,
    ) {
    }

    /**
     * Block a single IP address.
     */
    public function blockIp(string $ipAddress): void
    {
        $this->blockMany([$ipAddress]);
    }

    /**
     * Unblock a single IP address.
     */
    public function unblockIp(string $ipAddress): void
    {
        $this->unblockMany([$ipAddress]);
    }

    /**
     * Determine if a single IP is blocked.
     */
    public function isBlocked(string $ipAddress): bool
    {
        $ip = $this->normalizeIp($ipAddress);
        [, $managed, ] = $this->readSections();
        $entries = $this->parseManaged($managed);
        return in_array($ip, $entries, true);
    }

    /**
     * Block multiple IP addresses in a single atomic update.
     *
     * - Validates and normalizes all IPs first; if any is invalid, throws and does not modify the file.
     * - Idempotent: duplicate IPs are ignored; existing entries preserved; order remains stable.
     *
     * @param list<string> $ipAddresses
     */
    public function blockMany(array $ipAddresses): void
    {
        if ($ipAddresses === []) {
            return; // nothing to do
        }

        // Normalize all first to ensure all-or-nothing semantics
        $toAdd = [];
        foreach ($ipAddresses as $ipAddress) {
            $toAdd[] = $this->normalizeIp((string)$ipAddress);
        }

        $this->mutate(static function (array $entries) use ($toAdd): array {
            foreach ($toAdd as $ip) {
                if (!in_array($ip, $entries, true)) {
                    $entries[] = $ip;
                }
            }

            return $entries;
        });
    }

    /**
     * Unblock multiple IP addresses in a single atomic update.
     *
     * - Validates and normalizes all IPs first; if any is invalid, throws and does not modify the file.
     * - Idempotent: removing non-existent IPs is a no-op.
     *
     * @param list<string> $ipAddresses
     */
    public function unblockMany(array $ipAddresses): void
    {
        if ($ipAddresses === []) {
            return; // nothing to do
        }

        $toRemove = [];
        foreach ($ipAddresses as $ipAddress) {
            $toRemove[] = $this->normalizeIp((string)$ipAddress);
        }

        $removeSet = array_flip($toRemove);
        $this->mutate(static fn(array $entries): array => array_values(array_filter(
            $entries,
            static fn(string $existing): bool => !isset($removeSet[$existing]),
        )));
    }

    /**
     * Serialise concurrent block/unblock writers via flock on a sidecar lock
     * file. The lock file is `${htaccessPath}.lock`; it lives next to the
     * htaccess and is never renamed, so an advisory flock on it remains
     * coherent across the atomic rename inside writeSections().
     *
     * @param callable(list<string>): list<string> $mutator
     */
    private function mutate(callable $mutator): void
    {
        // Validate the parent directory before opening the lock so the
        // existing "Directory does not exist:" error surfaces ahead of any
        // filesystem side-effect of creating the lock file.
        $dir = dirname($this->htaccessPath);
        if (!is_dir($dir)) {
            throw new RuntimeException('Directory does not exist: ' . $dir);
        }

        $lockPath = $this->htaccessPath . '.lock';
        $lockHandle = @fopen($lockPath, 'c');
        if ($lockHandle === false) {
            throw new RuntimeException('Failed to open lock file: ' . $lockPath);
        }

        try {
            if (!flock($lockHandle, LOCK_EX)) {
                throw new RuntimeException('Failed to acquire exclusive lock on ' . $lockPath);
            }

            [$before, $managed, $after] = $this->readSections();
            $existingEntries = $this->parseManaged($managed);
            $entries = $mutator($existingEntries);

            // Skip the full read-modify-rewrite when the managed entry set is unchanged and the
            // section is already in the current format. Without this, an already-blocked client
            // that keeps hitting the firewall drives an O(file) rewrite under the exclusive lock
            // on every request. A section in any other form (notably the bare "Require not ip"
            // lines older versions wrote, which make Apache answer HTTP 500) is rewritten once.
            if ($entries === $existingEntries && $this->isCurrentFormat($managed, $entries)) {
                return;
            }

            $this->writeSections($before, $entries, $after);
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
    }

    private function normalizeIp(string $ipAddress): string
    {
        $ipAddress = trim($ipAddress);
        if ('' === $ipAddress) {
            throw new InvalidArgumentException('IP address must not be empty');
        }

        $isV4 = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

        if (!$isV4 && !$isV6) {
            throw new InvalidArgumentException('Invalid IP address: ' . $ipAddress);
        }

        // For IPv6, ensure compressed canonical form to avoid duplicates in different forms
        if ($isV6) {
            $packed = @inet_pton($ipAddress);
            if ($packed === false) {
                throw new InvalidArgumentException('Invalid IPv6 address: ' . $ipAddress);
            }

            $normalized = inet_ntop($packed);
            if ($normalized === false) {
                throw new InvalidArgumentException('Invalid IPv6 address: ' . $ipAddress);
            }

            $ipAddress = $normalized;
        }

        return $ipAddress;
    }

    /**
     * @return array{0:string,1:string,2:string}
    */
    private function readSections(): array
    {
        $content = '';
        if (file_exists($this->htaccessPath)) {
            $content = (string) @file_get_contents($this->htaccessPath);
        }

        if ($content === '') {
            // No managed section yet
            return [$content, '', ''];
        }

        $beginPos = strpos($content, self::BEGIN_MARK);
        $endPos   = strpos($content, self::END_MARK);

        if ($beginPos === false || $endPos === false || $endPos < $beginPos) {
            // No managed section yet
            return [$content, '', ''];
        }

        $before = substr($content, 0, $beginPos);
        $managed = substr(
            $content,
            $beginPos + strlen(self::BEGIN_MARK),
            $endPos - ($beginPos + strlen(self::BEGIN_MARK))
        );
        $after = substr($content, $endPos + strlen(self::END_MARK));

        return [$before, $managed, $after];
    }

    /**
     * Whether the managed body (content between the markers) is exactly what writeSections()
     * produces for the given entries. A file without a managed section counts as current while
     * there is nothing to block, so a no-op call never creates or touches the file.
     *
     * @param list<string> $entries
     */
    private function isCurrentFormat(string $managedBody, array $entries): bool
    {
        if ($managedBody === '' && $entries === []) {
            return true;
        }

        return $managedBody === "\n" . $this->renderManaged($entries);
    }

    /**
     * Render the lines between the markers, each terminated by a newline. Empty for no entries.
     *
     * @param list<string> $entries
     */
    private function renderManaged(array $entries): string
    {
        if ($entries === []) {
            return '';
        }

        $lines = self::BLOCK_OPEN;
        foreach ($entries as $entry) {
            $lines[] = '        Require not ip ' . $entry;
        }

        array_push($lines, ...self::BLOCK_CLOSE);

        return implode("\n", $lines) . "\n";
    }

    /**
     * Collects the "Require not ip" entries of the managed section. Every other line - the
     * <If>/<RequireAll> wrapper, "AuthMerging And", "Require all granted" - is ignored, so both
     * the current format and the bare lines written by older versions are read.
     *
     * @param string $managedBody Content between markers (excluding markers)
     * @return list<string> list of IP addresses
     */
    private function parseManaged(string $managedBody): array
    {
        $lines = preg_split('/\r?\n/', trim($managedBody)) ?: [];
        $entries = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            // Expect lines like: Require not ip 1.2.3.4
            if (preg_match('/^Require\s+not\s+ip\s+(.+)$/i', $line, $m) === 1) {
                $ip = trim($m[1]);
                if ($ip !== '') {
                    $entries[] = $ip;
                }
            }
        }

        // Keep unique and stable order
        $entries = array_values(array_unique($entries));
        return $entries;
    }

    /**
     * @param list<string> $entries
     */
    private function writeSections(string $before, array $entries, string $after): void
    {
        $managedBody = $this->renderManaged($entries);

        $newContent = rtrim($before)
            . (rtrim($before) === '' ? '' : "\n\n")
            . self::BEGIN_MARK . "\n"
            . $managedBody
            . self::END_MARK
            . (rtrim($after) === '' ? "\n" : "\n\n")
            . ltrim($after);

        $dir = dirname($this->htaccessPath);
        if (!is_dir($dir)) {
            throw new RuntimeException('Directory does not exist: ' . $dir);
        }

        $tmp = $this->htaccessPath . '.tmp.' . bin2hex(random_bytes(6));
        $bytes = @file_put_contents($tmp, $newContent);
        if ($bytes === false) {
            throw new RuntimeException('Failed to write temp file: ' . $tmp);
        }

        // Try to preserve permissions if file exists
        if (file_exists($this->htaccessPath)) {
            @chmod($tmp, fileperms($this->htaccessPath) & 0777);
        }

        // Atomic replace
        if (!@rename($tmp, $this->htaccessPath)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to atomically replace htaccess file');
        }
    }
}
