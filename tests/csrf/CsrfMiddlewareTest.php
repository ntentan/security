<?php

namespace ntentan\security\tests\csrf;

use ntentan\security\csrf\CsrfMiddleware;
use ntentan\sessions\SessionStore;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class CsrfMiddlewareTest extends TestCase
{
    private function getNextCallable(&$called)
    {
        return function ($req, $res) use (&$called) {
            $called = true;
            return $res;
        };
    }

    public function testGetRequestGeneratesTokenIfNotSet()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('has')->with('csrf_token')->willReturn(false);
        $sessionStore->expects($this->once())->method('set')->with('csrf_token', $this->callback('is_string'));

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');

        $response = $this->createMock(ResponseInterface::class);
        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new CsrfMiddleware($sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testGetRequestDoesNotGenerateTokenIfSet()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('has')->with('csrf_token')->willReturn(true);
        $sessionStore->expects($this->never())->method('set');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');

        $response = $this->createMock(ResponseInterface::class);
        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new CsrfMiddleware($sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testPostRequestFailsWithoutToken()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('has')->with('csrf_token')->willReturn(true);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(403)->willReturnSelf();

        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new CsrfMiddleware($sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertFalse($called);
        $this->assertSame($response, $result);
    }

    public function testPostRequestFailsWithInvalidToken()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('has')->with('csrf_token')->willReturn(true);
        $sessionStore->expects($this->once())->method('get')->with('csrf_token')->willReturn('valid_token');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->once())->method('getParsedBody')->willReturn(['csrf_token' => 'invalid_token']);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(403)->willReturnSelf();

        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new CsrfMiddleware($sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertFalse($called);
        $this->assertSame($response, $result);
    }

    public function testPostRequestPassesWithValidToken()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $sessionStore->expects($this->once())->method('has')->with('csrf_token')->willReturn(true);
        $sessionStore->expects($this->once())->method('get')->with('csrf_token')->willReturn('valid_token');
        $sessionStore->expects($this->never())->method('set');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->once())->method('getParsedBody')->willReturn(['csrf_token' => 'valid_token']);

        $response = $this->createMock(ResponseInterface::class);
        
        $called = false;
        $next = $this->getNextCallable($called);

        $middleware = new CsrfMiddleware($sessionStore);
        $result = $middleware->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testConfigure()
    {
        $sessionStore = $this->createMock(SessionStore::class);
        $middleware = new CsrfMiddleware($sessionStore);
        $middleware->configure(['key' => 'value']);
        $this->assertTrue(true); // Just to test it doesn't crash
    }
}
