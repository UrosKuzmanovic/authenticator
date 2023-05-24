<?php

namespace App\Manager;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\User\UserInterface;

class UserManager
{


    private UserRepository $repository;

    public function __construct(
        UserRepository $repository
    )
    {
        $this->repository = $repository;
    }

    /**
     * @param User $user
     * @return User
     */
    public function add(User $user): User
    {
        return $this->repository->add($user);
    }

    /**
     * @param string $email
     * @return UserInterface|null
     */
    public function loadUserByIdentifier(string $email): ?UserInterface
    {
        return $this->repository->loadUserByIdentifier($email);
    }
}