<?php

namespace ntentan\security\tests\auth;

use ntentan\security\auth\AuthMiddleware;
use ntentan\security\auth\providers\AuthProviderFactory;
use ntentan\security\auth\providers\AuthProvider;
use ntentan\sessions\SessionStore;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class AuthMiddlewareTest extends TestCase
{
    private function getNextCallable(&$called)
    {
        return function ($req, $res) use (&$called) {
            $called = true;
            return $res;
        };
    }

    public function testAuthenticatedSessionPassesThrough()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('get')->with('authenticated')->willReturn(true);

        $authMethodFactory = $this->createMock(AuthProviderFactory::class);
        $authMethodFactory->expects($this->never())->method('create');

        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new AuthMiddleware($authMethodFactory, $sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testExcludedPathPassesThrough()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('get')->with('authenticated')->willReturn(false);

        $authMethodFactory = $this->createMock(AuthProviderFactory::class);
        $authMethodFactory->expects($this->never())->method('create');

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->once())->method('getPath')->willReturn('/login');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getUri')->willReturn($uri);

        $response = $this->createMock(ResponseInterface::class);

        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new AuthMiddleware($authMethodFactory, $sessionStore);
        $middleware->configure(['excluded' => ['/login']]);
        $result = $middleware->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testUnauthenticatedSessionExecutesAuthProvider()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('get')->with('authenticated')->willReturn(false);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->once())->method('getPath')->willReturn('/dashboard');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getUri')->willReturn($uri);

        $response = $this->createMock(ResponseInterface::class);

        $authResponse = $this->createMock(ResponseInterface::class);

        $authProvider = $this->createMock(AuthProvider::class);
        $authProvider->expects($this->once())->method('run')->willReturn($authResponse);

        $authMethodFactory = $this->createMock(AuthProviderFactory::class);
        $authMethodFactory->expects($this->once())->method('create')->willReturn($authProvider);

        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new AuthMiddleware($authMethodFactory, $sessionStore);
        $middleware->configure(['excluded' => ['/login']]);
        
        $result = $middleware->run($request, $response, $next);

        $this->assertFalse($called);
        $this->assertSame($authResponse, $result);
    }
}
