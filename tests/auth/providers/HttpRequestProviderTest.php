<?php

namespace ntentan\security\tests\auth\providers;

use ntentan\Context;
use ntentan\exceptions\NtentanException;
use ntentan\security\auth\model\AuthUserModel;
use ntentan\security\auth\model\AuthUserModelFactory;
use ntentan\security\auth\providers\HttpRequestProvider;
use ntentan\sessions\SessionStore;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class HttpRequestProviderTest extends TestCase
{
    private function getNextCallable(&$called)
    {
        return function ($req, $res) use (&$called) {
            $called = true;
            return $res;
        };
    }

    public function testConfigureSetsUserModel()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);
        
        $userModelFactory->expects($this->once())->method('setModelClass')->with('MyUserModel');

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure(['user_model' => 'MyUserModel']);
    }

    public function testRunSkipsLoginPathWithGetMethod()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->any())->method('getPath')->willReturn('/login');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getUri')->willReturn($uri);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');

        $response = $this->createMock(ResponseInterface::class);
        $called = false;
        $next = $this->getNextCallable($called);

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure(['login_path' => '/login']);
        $result = $provider->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testRunRedirectsToLoginIfNotLoginPath()
    {
        $context = $this->createMock(Context::class);
        $context->expects($this->once())->method('getPath')->with('/login')->willReturn('/app/login');

        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->any())->method('getPath')->willReturn('/dashboard');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getUri')->willReturn($uri);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(302)->willReturnSelf();
        $response->expects($this->once())->method('withHeader')->with('Location', '/app/login')->willReturnSelf();

        $called = false;
        $next = $this->getNextCallable($called);

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure(['login_path' => '/login']);
        $result = $provider->run($request, $response, $next);

        $this->assertFalse($called);
        $this->assertSame($response, $result);
    }

    public function testRunAuthenticatesUser()
    {
        $session = $this->createMock(SessionStore::class);
        $session->expects($this->exactly(2))->method('set')
            ->willReturnCallback(function($key, $value) {
                if ($key === 'authenticated') $this->assertTrue($value);
                if ($key === 'user') $this->assertEquals(['id' => 1], $value);
            });

        $context = $this->createMock(Context::class);
        $context->expects($this->once())->method('getSession')->willReturn($session);
        $context->expects($this->once())->method('getPath')->with('/')->willReturn('/app/');

        $userModel = $this->createMock(AuthUserModel::class);
        $userModel->expects($this->once())->method('getPassword')->with('user1')->willReturn('hashed_pass');
        $userModel->expects($this->once())->method('getSessionData')->with('user1')->willReturn(['id' => 1]);

        $userModelFactory = $this->createMock(AuthUserModelFactory::class);
        $userModelFactory->expects($this->once())->method('create')->willReturn($userModel);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->any())->method('getPath')->willReturn('/login');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getUri')->willReturn($uri);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->any())->method('getParsedBody')->willReturn([
            'username' => 'user1',
            'password' => 'secret'
        ]);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(302)->willReturnSelf();
        $response->expects($this->once())->method('withHeader')->with('Location', '/app/')->willReturnSelf();

        $called = false;
        $next = $this->getNextCallable($called);

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure([
            'login_path' => '/login',
            'verify_passwords_with' => function($pass, $hash) {
                return $pass === 'secret' && $hash === 'hashed_pass';
            }
        ]);
        $result = $provider->run($request, $response, $next);

        $this->assertFalse($called);
        $this->assertSame($response, $result);
    }

    public function testRunFailsAuthenticationWithInvalidPassword()
    {
        $context = $this->createMock(Context::class);

        $userModel = $this->createMock(AuthUserModel::class);
        $userModel->expects($this->once())->method('getPassword')->with('user1')->willReturn('hashed_pass');

        $userModelFactory = $this->createMock(AuthUserModelFactory::class);
        $userModelFactory->expects($this->once())->method('create')->willReturn($userModel);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->any())->method('getPath')->willReturn('/login');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getUri')->willReturn($uri);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->any())->method('getParsedBody')->willReturn([
            'username' => 'user1',
            'password' => 'wrong'
        ]);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(401, "Invalid username or password")->willReturnSelf();

        $called = false;
        $next = $this->getNextCallable($called);

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure([
            'login_path' => '/login',
            'verify_passwords_with' => function($pass, $hash) {
                return false;
            }
        ]);
        $result = $provider->run($request, $response, $next);

        $this->assertTrue($called);
        $this->assertSame($response, $result);
    }

    public function testRunThrowsExceptionIfVerifyPasswordsWithNotSet()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->any())->method('getPath')->willReturn('/login');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getUri')->willReturn($uri);
        $request->expects($this->any())->method('getMethod')->willReturn('POST');
        $request->expects($this->any())->method('getParsedBody')->willReturn([]);

        $response = $this->createMock(ResponseInterface::class);
        $called = false;
        $next = $this->getNextCallable($called);

        $provider = new HttpRequestProvider($context, $userModelFactory);
        $provider->configure([
            'login_path' => '/login'
        ]);

        $this->expectException(NtentanException::class);
        $this->expectExceptionMessage("A password verification function was not specified for the HTTP authentication method");

        $provider->run($request, $response, $next);
    }
}
