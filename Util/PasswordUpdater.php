<?php

/*
 * This file is part of the FOSUserBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\UserBundle\Util;

use Exception;
use FOS\UserBundle\Model\UserInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\PasswordHasher\LegacyPasswordHasherInterface;

/**
 * Class updating the hashed password in the user when there is a new password.
 *
 * @author Christophe Coevoet <stof@notk.org>
 */
class PasswordUpdater implements PasswordUpdaterInterface
{
    /**
     * @var PasswordHasherFactoryInterface
     */
    private $passwordHasherFactory;

    /**
     * @param PasswordHasherFactoryInterface $passwordHasherFactory
     */
    public function __construct(PasswordHasherFactoryInterface $passwordHasherFactory)
    {
        $this->passwordHasherFactory = $passwordHasherFactory;
    }

    /**
     * @param UserInterface $user
     */
    public function hashPassword(UserInterface $user): void
    {
        $plainPassword = $user->getPlainPassword();

        if (empty($plainPassword)) {
            return;
        }

        $passwordHasher = $this->passwordHasherFactory->getPasswordHasher($user);

        /** @var string $hashedPassword */
        if ($passwordHasher instanceof LegacyPasswordHasherInterface) {
            $salt = $this->createSalt();
            $user->setSalt($salt);

            $hashedPassword = $passwordHasher->hash($plainPassword, $user->getSalt());
        } else {
            $user->setSalt(null);

            $hashedPassword = $passwordHasher->hash($plainPassword);
        }

        $user->setPassword($hashedPassword);
        $user->eraseCredentials();
    }

    /**
     * @return string
     */
    private function createSalt(): string
    {
        /** @var string $bytes */
        try {
            $bytes = random_bytes(32);
        } catch (Exception $e) {
            $bytes = '';
        }

        return rtrim(str_replace('+', '.', base64_encode($bytes)), '=');
    }
}
