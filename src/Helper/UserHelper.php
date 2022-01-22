<?php
namespace App\Helper;

use App\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactory;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher;

class UserHelper
{
    public static function getUserFromRequest(Request $request, PasswordHasherFactory $passwordHasherFactory) :User
    {
        $user = new User();
        $user->setIsEnabled(true);
        $user->setEmail($request->request->get('_username'));
        $user->setName($request->request->get('_username'));
        // Hash password
        $userPasswordHasher = new UserPasswordHasher($passwordHasherFactory);
        // hash the password (based on the security.yaml config for the $user class)
        $hashedPassword = $userPasswordHasher->hashPassword(
            $user,
            $request->request->get('_password')
        );
        $user->setPassword($hashedPassword);
        return $user;
    }

}