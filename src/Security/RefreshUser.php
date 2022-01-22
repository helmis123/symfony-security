<?php

namespace App\Security;

use App\BrowserKit\TestBrowserToken;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class RefreshUser
{
    public function __invoke($token, UserProviderInterface $userProvider)
    {
        /** @var TestBrowserToken $token */
        $user = $token->getUser();
        if ($user !== $userProvider->loadUserByIdentifier($user->getUserIdentifier())) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }
    }

}