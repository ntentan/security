<?php

namespace ntentan\security\tests\auth;

use ntentan\Context;
use ntentan\security\auth\model\AuthUserModelFactory;
use ntentan\security\auth\providers\AuthProvider;
use ntentan\security\auth\providers\AuthProviderFactory;
use ntentan\security\auth\providers\HttpRequestProvider;
use PHPUnit\Framework\TestCase;

class AuthProviderFactoryTest extends TestCase
{
    public function testCreateDefaultHttpRequestProvider()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $factory = new AuthProviderFactory($context, $userModelFactory);
        $provider = $factory->create([]);

        $this->assertInstanceOf(HttpRequestProvider::class, $provider);
    }

    public function testCreateRegisteredProvider()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $customProvider = $this->createMock(AuthProvider::class);
        $customProvider->expects($this->once())->method('configure')->with(['method' => 'custom']);

        $factory = new AuthProviderFactory($context, $userModelFactory);
        $factory->registerAuthMethod('custom', function() use ($customProvider) {
            return $customProvider;
        });

        $provider = $factory->create(['method' => 'custom']);

        $this->assertSame($customProvider, $provider);
    }

    public function testCreateThrowsExceptionForUnknownProvider()
    {
        $context = $this->createMock(Context::class);
        $userModelFactory = $this->createMock(AuthUserModelFactory::class);

        $factory = new AuthProviderFactory($context, $userModelFactory);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage("Auth method unknown not found");

        $factory->create(['method' => 'unknown']);
    }
}
