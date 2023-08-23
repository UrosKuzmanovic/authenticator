<?php

namespace App\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use App\Repository\UserRepository;

class AppUserProvider implements UserProviderInterface
{

    /** @var UserRepository */
    private UserRepository $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function loadUserByIdentifier(string $identifier): ?UserInterface
    {
        return $this->userRepository->findOneBy([
            'email' => $identifier,
            'enabled' => true,
        ]);
    }

    public function loadUserByUsername(string $username): UserInterface
    {
        // This method is deprecated and won't be used, so it can be left empty or throw an exception
        throw new UnsupportedUserException('The "loadUserByUsername" method is deprecated and should not be used.');
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        // Implement logic to refresh the user if needed
        // For example, if the user's roles or other details change in the database
        throw new UnsupportedUserException('User is not supported to refresh.');
    }

    public function supportsClass(string $class): bool
    {
        return $class === 'App\Entity\User';
    }
}