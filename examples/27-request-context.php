<?php

/**
 * Example 27: Request Context for Post-Handler Fail2Ban
 *
 * This example demonstrates the RequestContext API, which lets your application
 * code signal fail2ban events from inside the request handler — after the
 * firewall has already passed the request through.
 *
 * Features shown:
 * - Retrieving the RequestContext from a PSR-7 request attribute
 * - Calling recordFailure() to signal failed login attempts
 * - Automatic processing of recorded failures by the middleware
 * - Accessing the FirewallResult via getResult()
 * - Null-safe access pattern for safety
 *
 * Run: php examples/27-request-context.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

echo "=== Request Context Example ===\n\n";

// =============================================================================
// CONFIGURATION
// =============================================================================

echo "--- Setup ---\n\n";

$cache = new InMemoryCache();
$config = new Config($cache);
$config->enableResponseHeaders();

// Configure a fail2ban rule for login failures.
// With RequestContext, the filter always returns false — failures are recorded
// programmatically by the handler, not matched by the firewall pre-handler.
$config->fail2ban->add(
    name: 'login-failures',
    threshold: 3,
    period: 300,
    ban: 3600,
    filter: fn(ServerRequestInterface $serverRequest): bool => false,
    key: KeyExtractors::ip(),
);

echo "  Fail2Ban rule 'login-failures': 3 failures in 5 min = 1 hour ban\n";

$psr17Factory = new Psr17Factory();
$middleware = new Middleware($config, $psr17Factory);

echo "  Middleware created with RequestContext support\n\n";

// =============================================================================
// MOCK HANDLER
// =============================================================================

// A handler that simulates a login endpoint. It uses the RequestContext API
// to signal failures instead of relying on headers.
$loginHandler = new class () implements RequestHandlerInterface {
    /** @var array<string, string> valid credentials */
    private array $validCredentials = [
        'alice' => 'correct-password',
    ];

    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $path = $serverRequest->getUri()->getPath();

        if ($path !== '/login') {
            return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
        }

        $username = $serverRequest->getHeaderLine('X-Username');
        $password = $serverRequest->getHeaderLine('X-Password');

        // Retrieve the RequestContext attached by the middleware
        /** @var RequestContext|null $context */
        $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);

        // Check credentials
        $validPassword = $this->validCredentials[$username] ?? null;
        if ($validPassword === null || $password !== $validPassword) {
            // Signal the failure via RequestContext
            $ip = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
            $context?->recordFailure('login-failures', $ip);

            return new Response(
                401,
                ['Content-Type' => 'application/json'],
                json_encode(['error' => 'Invalid credentials'], JSON_THROW_ON_ERROR)
            );
        }

        return new Response(
            200,
            ['Content-Type' => 'application/json'],
            json_encode(['success' => true, 'user' => $username], JSON_THROW_ON_ERROR)
        );
    }
};

// =============================================================================
// HELPER
// =============================================================================

$testRequest = function (
    string $description,
    string $path,
    array $headers = [],
    string $ip = '10.0.0.50',
) use ($middleware, $loginHandler): ResponseInterface {
    $request = new ServerRequest('POST', $path, $headers, null, '1.1', ['REMOTE_ADDR' => $ip]);
    $response = $middleware->process($request, $loginHandler);
    $status = $response->getStatusCode();

    echo sprintf("  %-55s => %d", $description, $status);

    $phirewallHeader = $response->getHeaderLine('X-Phirewall');
    if ($phirewallHeader !== '') {
        echo sprintf(' [%s]', strtoupper($phirewallHeader));
    }

    echo "\n";

    return $response;
};

// =============================================================================
// TEST 1: Successful Login
// =============================================================================

echo "--- Test 1: Successful login (no failure recorded) ---\n\n";

$testRequest(
    'POST /login alice:correct-password',
    '/login',
    ['X-Username' => 'alice', 'X-Password' => 'correct-password'],
);

echo "  -> Login succeeded. Context was available but recordFailure() was not called.\n\n";

// =============================================================================
// TEST 2: Failed Logins Recording Failures
// =============================================================================

echo "--- Test 2: Failed logins using RequestContext ---\n\n";

$attackerIp = '10.0.0.99';

for ($i = 1; $i <= 3; ++$i) {
    $testRequest(
        sprintf('POST /login attempt %d (wrong password)', $i),
        '/login',
        ['X-Username' => 'alice', 'X-Password' => 'wrong-password'],
        $attackerIp,
    );
}

echo "\n  -> 3 failures recorded via \$context->recordFailure(). Threshold reached.\n\n";

// =============================================================================
// TEST 3: Banned Request
// =============================================================================

echo "--- Test 3: Subsequent request is blocked by fail2ban ---\n\n";

$testRequest(
    'POST /login attempt 4 (should be banned)',
    '/login',
    ['X-Username' => 'alice', 'X-Password' => 'correct-password'],
    $attackerIp,
);

echo "  -> Even with correct credentials, the IP is now banned.\n\n";

// =============================================================================
// TEST 4: Other IPs Are Unaffected
// =============================================================================

echo "--- Test 4: Different IP is unaffected ---\n\n";

$testRequest(
    'POST /login from different IP',
    '/login',
    ['X-Username' => 'alice', 'X-Password' => 'correct-password'],
    '10.0.0.200',
);

echo "  -> Ban is per-IP; other clients are not affected.\n\n";

// =============================================================================
// TEST 5: Accessing the FirewallResult
// =============================================================================

echo "--- Test 5: Accessing the FirewallResult via context ---\n\n";

$resultHandler = new class () implements RequestHandlerInterface {
    public function handle(ServerRequestInterface $serverRequest): ResponseInterface
    {
        /** @var RequestContext|null $context */
        $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);

        if ($context !== null) {
            $result = $context->getResult();
            echo sprintf("  FirewallResult outcome : %s\n", $result->outcome->value);
            echo sprintf("  FirewallResult isPass  : %s\n", $result->isPass() ? 'true' : 'false');
            echo sprintf("  FirewallResult rule    : %s\n", $result->rule ?? '(none)');
        }

        return new Response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
};

$request = new ServerRequest('GET', '/dashboard', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.200']);
$middleware->process($request, $resultHandler);

echo "  -> The handler can inspect the firewall decision for logging or UI.\n\n";

// =============================================================================
// TEST 6: Null-Safe Access Pattern
// =============================================================================

echo "--- Test 6: Null-safe access pattern ---\n\n";

echo "  When your handler might run without the middleware (e.g. in tests),\n";
echo "  use the null-safe operator for safety:\n\n";
echo "    \$context = \$request->getAttribute(RequestContext::ATTRIBUTE_NAME);\n";
echo "    \$context?->recordFailure('login-failures', \$ip);\n\n";
echo "  If the middleware is not in the stack, \$context is null and the call\n";
echo "  is silently skipped — no errors, no side effects.\n\n";

echo "=== Example Complete ===\n";
