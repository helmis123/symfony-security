<?php

namespace App\Security;

use App\Authenticator\AppAuthenticator;
use App\BrowserKit\KernelBrowser;
use App\Helper\UserHelper;
use App\Provider\UserProvider;
use App\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactory;
use Symfony\Component\PasswordHasher\Hasher\Pbkdf2PasswordHasher;
use Symfony\Component\Security\Core\Authentication\RememberMe\InMemoryTokenProvider;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\EventListener\CheckCredentialsListener;
use Symfony\Component\Security\Http\EventListener\CsrfProtectionListener;
use Symfony\Component\Security\Http\EventListener\PasswordMigratingListener;
use Symfony\Component\Security\Http\EventListener\RememberMeListener;
use Symfony\Component\Security\Http\EventListener\UserProviderListener;
use Symfony\Component\Security\Http\RememberMe\PersistentRememberMeHandler;

class LoginCheck
{

    public static function getToken(
        Request $request,
        Response $response,
        UserProvider $userProvider,
        AppAuthenticator $appAuthenticator
    ): ?TokenInterface {
        $token = null;
        if ($request->request->get('_username') && $request->request->get('_password')) {
            $passwordHasherFactory = new PasswordHasherFactory([User::class => new Pbkdf2PasswordHasher()]);
            $user = UserHelper::getUserFromRequest($request, $passwordHasherFactory);
            // authenticate

            // generate passport
            $passport = $appAuthenticator->authenticate($request);
            // UserProvider check passport
            $checkPassportEvent = new CheckPassportEvent($appAuthenticator, $passport);
            $UserProviderListener = new UserProviderListener($userProvider);
            $UserProviderListener->checkPassport($checkPassportEvent);
            // check credential Listener
            $checkCredentialsListener = new CheckCredentialsListener($passwordHasherFactory);
            $checkCredentialsListener->checkPassport($checkPassportEvent);
            // Csrf Protection Listener
            $csrfTokenManager = new CsrfTokenManager();
            $csrfProtectionListener = new CsrfProtectionListener($csrfTokenManager);
            $csrfProtectionListener->checkPassport($checkPassportEvent);
            // Password Migrating Listener
            $KernelBrowser = new KernelBrowser();
            $token = $KernelBrowser->loginUser($user, $request);
            $passwordMigratingListener = new PasswordMigratingListener($passwordHasherFactory);
            $LoginSuccessEvent = new LoginSuccessEvent(
                $appAuthenticator, $passport, $token, $request, $response, 'main'
            );
            $passwordMigratingListener->onLoginSuccess($LoginSuccessEvent);
            // Remember Me Listener
            $inMemoryTokenProvider = new InMemoryTokenProvider();
            $secret = '440c8ed55f7a73d0a359fe7a0fca085b';
            // Remember Me Listener
            $requestStack = new RequestStack();
            $requestStack->push($request);
            $rememberMeHandler = new PersistentRememberMeHandler(
                $inMemoryTokenProvider,
                $secret,
                $userProvider,
                $requestStack,
                [],
                null,
                null
            );
            $rememberMeListener = new RememberMeListener($rememberMeHandler);
            $loginSuccessEvent = new LoginSuccessEvent(
                $appAuthenticator, $passport, $token, $request, $response, 'main'
            );
            $rememberMeListener->onSuccessfulLogin($loginSuccessEvent);
//            $userChecker = new InMemoryUserChecker($user);
//            $userCheckerListener = new UserCheckerListener($userChecker);
//            $userCheckerListener->preCheckCredentials($checkPassportEvent);
            $response->setContent($user->getUserIdentifier());
        }
        return $token;
    }


}