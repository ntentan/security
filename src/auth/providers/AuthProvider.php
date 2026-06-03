<?php
namespace ntentan\security\auth\providers;

use ntentan\middleware\Middleware;

interface AuthProvider extends Middleware
{
    function isAuthenticated(): bool;
}
