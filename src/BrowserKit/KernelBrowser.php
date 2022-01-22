<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\BrowserKit;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\User\UserInterface;

class KernelBrowser
{



    /**
     * @param UserInterface $user
     *
     * @return $this
     */
    public function loginUser(object $user,Request $request,  string $firewallContext = 'main'): TestBrowserToken
    {
        if (!interface_exists(UserInterface::class)) {
            throw new \LogicException(sprintf('"%s" requires symfony/security-core to be installed.', __METHOD__));
        }

        if (!$user instanceof UserInterface) {
            throw new \LogicException(sprintf('The first argument of "%s" must be instance of "%s", "%s" provided.', __METHOD__, UserInterface::class, \is_object($user) ? \get_class($user) : \gettype($user)));
        }
        $token = new TestBrowserToken($user->getRoles(), $user, $firewallContext);
        // required for compatibility with Symfony 5.4
//        if (method_exists($token, 'isAuthenticated')) {
//            $token->setAuthenticated(true, false);
//        }

//        $container = $this->getContainer();
//        $container->get('security.untracked_token_storage')->setToken($token);
        if (!$request->hasSession()) {
            return $this;
        }

        $session = new Session();
        $session->set('_security_'.$firewallContext, serialize($token));
        $session->save();
        $request->setSession($session);

        $cookie = new Cookie($session->getName(), $session->getId());
        return $token;
    }


}
