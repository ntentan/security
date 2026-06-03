<?php

namespace ntentan\security\auth\model;

/**
 * The authentication user
 */
interface AuthUserModel
{
    function getPassword(string $username): string;
    function getSessionData(string $username): array;
}