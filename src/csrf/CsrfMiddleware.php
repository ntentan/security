<?php

namespace ntentan\security\csrf;

use ntentan\middleware\Middleware;
use ntentan\sessions\SessionStore;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

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
            $csrfToken = $request->getParsedBody()['csrf_token'] ?? null;
            $sessionToken = $this->sessionStore->get('csrf_token');
            if (!is_string($csrfToken) || !is_string($sessionToken) || !hash_equals($sessionToken, $csrfToken)) {
                return $response->withStatus(403);
            }
        }
        $this->setupToken();
        return $next($request, $response);
    }

    private function setupToken() : void
    {
        if (!$this->csrfTokenSet) {
            $this->sessionStore->set('csrf_token', bin2hex(random_bytes(32)));
        }
    }

    public function configure(array $configuration)
    {
        $this->config = $configuration;
    }
}
