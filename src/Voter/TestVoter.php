<?php

use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Security;

class TestVoter
{

    public function __construct(Security $security)
    {
        $this->security = $security;
    }

    protected function voteOnAttribute($attribute, $subject, AuthorizationChecker $authorizationChecker): bool
    {
        return $authorizationChecker->isGranted('ROLE_SUPER_ADMIN') ;
    }
}
