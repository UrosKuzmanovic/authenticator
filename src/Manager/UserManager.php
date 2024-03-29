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
    public function save(User $user): User
    {
        return $this->repository->save($user);
    }

    /**
     * @param string $email
     * @return UserInterface|null
     */
    public function loadUserByIdentifier(string $email): ?UserInterface
    {
        return $this->repository->loadUserByIdentifier($email);
    }

    /**
     * @param array $criteria
     * @return User|null
     */
    public function findOneBy(array $criteria): ?User
    {
        return $this->repository->findOneBy($criteria);
    }

    /**
     * @param string $email
     * @param string $code
     * @return User|null
     */
    public function confirmUser(string $email, string $code): ?User
    {
        $userDB = $this->repository->findOneBy([
            'email' => $email,
            'confirmationCode' => $code,
            'enabled' => false
        ]);

        if ($userDB && $userDB->getId()) {
            $this->repository->save(
                $userDB
                    ->setEnabled(true)
                    ->setConfirmationCode(null)
            );
        }

        return $userDB;
    }
}