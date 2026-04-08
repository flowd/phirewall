--TEST--
Phirewall: rate limit headers present on 200 and 429 responses
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;

$clock = new FakeClock(1700000000.0);
$cache = new InMemoryCache($clock);
$config = new Config($cache, null, $clock);
$config->enableRateLimitHeaders();
$config->throttles->add('api', 3, 60, fn($r) => 'test-key');

$middleware = phpt_middleware($config);
$handler = phpt_handler();

// First request: allowed, rate limit headers should reflect current usage
$first = $middleware->process(phpt_request('GET', '/'), $handler);
echo 'status=' . $first->getStatusCode() . "\n";
echo 'ratelimit-limit=' . $first->getHeaderLine('X-RateLimit-Limit') . "\n";
echo 'ratelimit-remaining=' . $first->getHeaderLine('X-RateLimit-Remaining') . "\n";

// Exhaust the remaining quota (requests 2 and 3 still pass)
$middleware->process(phpt_request('GET', '/'), $handler);
$middleware->process(phpt_request('GET', '/'), $handler);

// Fourth request: exceeds limit, should return 429 with Retry-After
$throttled = $middleware->process(phpt_request('GET', '/'), $handler);
echo 'status=' . $throttled->getStatusCode() . "\n";
echo 'retry-after=' . $throttled->getHeaderLine('Retry-After') . "\n";
?>
--EXPECT--
status=200
ratelimit-limit=3
ratelimit-remaining=2
status=429
retry-after=40
