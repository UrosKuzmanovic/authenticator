<?php

namespace App\Entity\Dto;

use App\Entity\User;
use Symfony\Component\Security\Core\User\UserInterface;

class LoginDto
{

    private ?UserInterface $user = null;

    private ?string $token = null;

    /**
     * @return UserInterface|null
     */
    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    /**
     * @param UserInterface|null $user
     * @return LoginDto
     */
    public function setUser(?UserInterface $user): LoginDto
    {
        $this->user = $user;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * @param string|null $token
     * @return LoginDto
     */
    public function setToken(?string $token): LoginDto
    {
        $this->token = $token;
        return $this;
    }
}