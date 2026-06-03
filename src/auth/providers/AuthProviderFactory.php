<?php
namespace ntentan\security\auth\providers;

use ntentan\Context;
use ntentan\security\auth\model\AuthUserModelFactory;

/**
 * A factory for creating authentication provider.
 * 
 * @author ekow
 */
class AuthProviderFactory
{
    private array $factories = [];

    public function __construct(Context $context, AuthUserModelFactory $userModelFactory) {
        $this->factories = [
            'http_request' => function() use ($context, $userModelFactory) {
                return new HttpRequestProvider($context, $userModelFactory);
            },
        ];
    }

    public function create(array $config): AuthProvider
    {
        $authMethodType = $config['method'] ?? 'http_request';
        if (!isset($this->factories[$authMethodType])) {
            throw new \Exception("Auth method $authMethodType not found");
        }
        $instance = $this->factories[$authMethodType]();
        $instance->configure($config);
        return $instance;
    }

    public function registerAuthMethod(string $name, callable $class) : void
    {
        $this->factories[$name] = $class;
    }
}
