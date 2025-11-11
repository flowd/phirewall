<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Owasp;

use Flowd\Phirewall\Owasp\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetPmBoundaryTest extends TestCase
{
    public function testPmMatchesAtCapBoundary(): void
    {
        // Build a phrase list with exactly 5000 unique phrases with zero-padded numbers to avoid substring overlaps
        $phrases = [];
        for ($i = 1; $i <= 5000; ++$i) {
            $phrases[] = 'p' . sprintf('%04d', $i);
        }

        $list = implode(',', $phrases);
        $rulesText = 'SecRule REQUEST_URI "@pm ' . $list . '" "id:510000,phase:2,deny,msg:\'PM boundary match\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        // Should match when URI contains the last phrase within the cap
        $serverRequest = new ServerRequest('GET', '/foo/p5000/bar');
        $this->assertSame(510000, $coreRuleSet->match($serverRequest));
    }

    public function testPmIgnoresPhrasesBeyondCap(): void
    {
        // Build a phrase list with 5001 phrases; the last one should be ignored by the cap
        // Use zero-padded numbers to avoid any phrase being a substring of another
        $phrases = [];
        for ($i = 1; $i <= 5001; ++$i) {
            $phrases[] = 'q' . sprintf('%04d', $i);
        }

        $list = implode(' ', $phrases); // mix separator styles (space is allowed)
        $rulesText = 'SecRule REQUEST_URI "@pm ' . $list . '" "id:510001,phase:2,deny,msg:\'PM beyond cap\'"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        // URI contains only the 5001st phrase which should have been ignored
        $reqNo = new ServerRequest('GET', '/only-q5001-here');
        $this->assertNull($coreRuleSet->match($reqNo));

        // But containing a phrase within the first 5000 should match
        $reqYes = new ServerRequest('GET', '/has-q4999-here');
        $this->assertSame(510001, $coreRuleSet->match($reqYes));
    }
}
