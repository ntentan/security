<?php
namespace ntentan\security\auth;

use ntentan\middleware\Middleware;

interface AuthProvider extends Middleware
{
    function isAuthenticated(): bool;
}
