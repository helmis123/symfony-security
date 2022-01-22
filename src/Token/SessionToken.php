<?php
namespace App\Token;
use App\BrowserKit\TestBrowserToken;
use Symfony\Component\HttpFoundation\Request;

class SessionToken
{
    public static function getTokenFromRequest(Request $request): ?TestBrowserToken
    {
        $session = $request->getSession();
        $serializedToken = $session->get('_security_main');
        return $serializedToken ? unserialize($serializedToken) : null;
    }
}