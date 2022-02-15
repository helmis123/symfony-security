<?php
namespace App\Voter;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

use TypeError;

class DefaultVoter extends Voter
{

    public function vote(TokenInterface $token, mixed $subject, array $attributes): int
    {
        // abstain vote by default in case none of the attributes are supported
        $vote = self::ACCESS_ABSTAIN;

        foreach ($attributes as $attribute) {
            try {
                if (!$this->supports($attribute, $subject)) {
                    continue;
                }
            } catch (TypeError $e) {
                if (false !== strpos($e->getMessage(), 'supports(): Argument #1')) {
                    continue;
                }

                throw $e;
            }

            // as soon as at least one attribute is supported, default is to deny access
            $vote = self::ACCESS_DENIED;

            if ($this->voteOnAttribute($attribute, $subject, $token)) {
                // grant access as soon as at least one attribute returns a positive response
                return self::ACCESS_GRANTED;
            }
        }

        return $vote;
    }
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token): bool
    {
        return true ;
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return true;
    }
}
