--TEST--
Phirewall: RequestContext::recordFailure() signals fail2ban bans after the handler returns
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Tests\Support\FakeClock;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

// threshold: 2 with post-handler semantics uses >= so the 2nd recorded failure triggers the ban.
$clock = new FakeClock();
$config = new Config(new InMemoryCache($clock));
$config->fail2ban->add(
    'login',
    threshold: 2,
    period: 300,
    ban: 3600,
    filter: fn() => false,
    key: KeyExtractors::ip(),
);

$middleware = phpt_middleware($config);

// Handler reads RequestContext and records a failure for the requesting IP.
$recordingHandler = new class implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $context = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
        if ($context instanceof RequestContext) {
            $ip = (string) ($request->getServerParams()['REMOTE_ADDR'] ?? '');
            $context->recordFailure('login', $ip);
        }

        return new Response(200, ['X-Handler' => 'ok']);
    }
};

// Request 1: failure recorded post-handler, count=1, 1 >= 2 is false → no ban, 200.
$request  = phpt_request('POST', '/login', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $recordingHandler);
echo 'status[1]=' . $response->getStatusCode() . "\n";

// Request 2: failure recorded post-handler, count=2, 2 >= 2 is true → IP banned, still 200
//            (handler already returned before the ban was applied).
$request  = phpt_request('POST', '/login', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $recordingHandler);
echo 'status[2]=' . $response->getStatusCode() . "\n";

// Request 3: firewall detects ban key before calling handler → 403.
$request  = phpt_request('GET', '/', ['REMOTE_ADDR' => '1.2.3.4']);
$response = $middleware->process($request, $recordingHandler);
echo 'status[3]=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
status[1]=200
status[2]=200
status[3]=403
