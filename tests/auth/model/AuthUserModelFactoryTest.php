<?php

namespace ntentan\security\tests\auth\model;

use ntentan\exceptions\NtentanException;
use ntentan\security\auth\model\AuthUserModel;
use ntentan\security\auth\model\AuthUserModelFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

class AuthUserModelFactoryTest extends TestCase
{
    public function testCreateReturnsModel()
    {
        $container = $this->createMock(ContainerInterface::class);
        $model = $this->createMock(AuthUserModel::class);

        $container->expects($this->once())->method('get')->with('MyUserModel')->willReturn($model);

        $factory = new AuthUserModelFactory($container);
        $factory->setModelClass('MyUserModel');

        $result = $factory->create();

        $this->assertSame($model, $result);
    }

    public function testCreateThrowsExceptionWhenModelClassNotSet()
    {
        $container = $this->createMock(ContainerInterface::class);

        $factory = new AuthUserModelFactory($container);

        $this->expectException(NtentanException::class);
        $this->expectExceptionMessage("A user model class name must be set");

        $factory->create();
    }
}
