<?php

namespace ntentan\security\csrf;

use ntentan\middleware\Middleware;
use ntentan\sessions\SessionStore;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ntentan\http\StringStream;

class CsrfMiddleware implements Middleware
{
    private bool $csrfTokenSet = false;
    private SessionStore $sessionStore;
    private array $config = [];

    public function __construct(SessionStore $sessionStore)
    {
        $this->csrfTokenSet = $sessionStore->has('csrf_token');
        $this->sessionStore = $sessionStore;
    }

    public function run(ServerRequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface
    {
        if (
            $request->getMethod() == "POST" || $request->getMethod() == "PUT" ||
            $request->getMethod() == "PATCH" || $request->getMethod() == "DELETE"
        ) {
            if (!$this->isExcluded($request->getUri()->getPath())) {
                $csrfToken = $request->getHeader('X-CSRF-Token')[0] ?? $request->getParsedBody()['csrf_token'] ?? null;
                $sessionToken = $this->sessionStore->get('csrf_token');
                if (!is_string($csrfToken) || !is_string($sessionToken) || !hash_equals($sessionToken, $csrfToken)) {
                    return $response->withStatus(403)->withBody(new StringStream('Forbidden: Invalid CSRF token'));
                }
            }
        }
        $this->setupToken();
        return $next($request, $response);
    }

    private function isExcluded(string $path): bool
    {
        $exceptions = $this->config['exceptions'] ?? [];
        foreach ($exceptions as $exception) {
            if (str_starts_with($exception, '/') && str_ends_with($exception, '/') && strlen($exception) > 2) {
                if (preg_match($exception, $path)) {
                    return true;
                }
            }
            if (str_starts_with($path, $exception)) {
                return true;
            }
        }
        return false;
    }

    private function setupToken() : void
    {
        if (!$this->csrfTokenSet) {
            $token = bin2hex(random_bytes(32));
            $this->sessionStore->set('csrf_token', $token);
            if ($this->config["set_cookie"] ?? false) {
                setcookie("CSRF_TOKEN", $token, [
                    "expires" => "",
                    "path" => "/",
                    "domain" => '',
                    "secure" => true,
                    "httponly" => false,
                    "samesite" => 'Lax',
                ]);
            }
        }
    }

    public function configure(array $configuration)
    {
        $this->config = $configuration;
    }
}
