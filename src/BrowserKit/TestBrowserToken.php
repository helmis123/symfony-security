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

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

class TestBrowserToken extends AbstractToken
{
    private string $firewallName;

    public function __construct(array $roles = [], UserInterface $user = null, string $firewallName = 'main')
    {
        parent::__construct($roles);

        if (null !== $user) {
            $this->setUser($user);
        }

        $this->firewallName = $firewallName;
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    public function getCredentials()
    {
        return null;
    }

    public function __serialize(): array
    {
        return [$this->firewallName, parent::__serialize()];
    }

    public function __unserialize(array $data): void
    {
        [$this->firewallName, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}
