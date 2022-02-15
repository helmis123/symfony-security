<?php

namespace App;


use App\Authenticator\AppAuthenticator;
use App\Provider\UserProvider;
use App\Security\LoginCheck;
use App\Token\SessionToken;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\Strategy\AffirmativeStrategy;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Role\RoleHierarchy;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\AccessMap;
use Symfony\Component\Security\Http\Firewall;
use Symfony\Component\Security\Http\FirewallMap;


class Kernel implements HttpKernelInterface
{

    public function handle(Request $request, $type = self::MAIN_REQUEST, $catch = true): Response
    {
        $response = new Response();
        $requestEvent = new RequestEvent($this, $request, $type);
        $requestEvent->setResponse($response);
        // access listener RoleVoter
        $token = SessionToken::getTokenFromRequest($request);
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($token);
        $userProvider = new UserProvider();
//        $csrfTokenManager = new CsrfTokenManager();
        $appAuthenticator = new AppAuthenticator();
        $token = $token ?:  LoginCheck::getToken($request, $response, $userProvider, $appAuthenticator);

//        else if(!$csrfTokenManager->isTokenValid($token)) {
//            throw new InvalidCsrfTokenException();
//        }


        // access control
        $requestMatcherAdmin = new RequestMatcher('^/');
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        $strategy =  new AffirmativeStrategy(true);
        $container = new  ContainerBuilder();
        $security = new Security($container);

        $accessDecisionManager = new AccessDecisionManager(
            [
                new RoleVoter(),
                new AuthenticatedVoter($authenticationTrustResolver),
                new RoleHierarchyVoter(
                    new RoleHierarchy([
                                          'ROLE_ADMIN' => ['ROLE_USER'],
                                          'ROLE_SUPER_ADMIN' => ['ROLE_ADMIN'],
                                      ])
                ),
            ],
            $strategy
        );

        $accessMap = new AccessMap();
        $accessMap->add($requestMatcherAdmin, ['ROLE_SUPER_ADMIN']);
//        $userProvider = new UserProvider();
//        if(!$accessDecisionManager->decide($token, ['ROLE_SUPER_ADMIN'])){
//            throw new AccessDeniedException();
//        }
        $accessListener = new Firewall\AccessListener(
            $tokenStorage,
            $accessDecisionManager,
            $accessMap,
        );
//        $accessListener->supports($request);
//        $accessListener->authenticate($requestEvent);
        // Authorization Checker
        $authorizationChecker = new AuthorizationChecker($tokenStorage, $accessDecisionManager, false);
        $container->set('security.authorization_checker', $authorizationChecker);
        $tokenStorage =  new TokenStorage();
        $tokenStorage->setToken($token);
        $container->set('security.token_storage', $tokenStorage);
//        dd($authenticationTrustResolver->isAuthenticated($token));
//        dd($authorizationChecker->isGranted('ROLE_ADMIN'));
//        $expressionVoter = new ExpressionVoter();
        $session = $request->getSession();
//        $voter = new TraceableVoter($authenticationTrustResolver);
//        dd(unserialize($session->get('_security_main')));
//        if($request->hasSession() && $request->getSession()->get('data')){
//
//        }
        // firewall
        $eventDispatcher = new EventDispatcher();
        $requestMatcherFirewall = new RequestMatcher('^/');
        $firewallMap = new FirewallMap();
        $firewallMap->add($requestMatcherFirewall, [$accessListener]);
        $firewall = new Firewall($firewallMap, $eventDispatcher);
        $eventDispatcher->addSubscriber($firewall);
        $requestEvent = new RequestEvent($this, $request, $type);
        try {
            $eventDispatcher->dispatch($requestEvent, KernelEvents::REQUEST);
        } catch (AccessDeniedException $accessDeniedException) {
            $response = new RedirectResponse('/login.php');
        } catch (BadCredentialsException $badCredentialsException) {
            $appAuthenticator->onAuthenticationFailure($request, $badCredentialsException);
        }
        return $response;
    }


}