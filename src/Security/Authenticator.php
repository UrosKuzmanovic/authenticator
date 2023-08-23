<?php

namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class Authenticator extends AbstractAuthenticator

{

    private JWTTokenManagerInterface $JWTManager;
    private AppUserProvider $userProvider;
    private PasswordHasherFactoryInterface $passwordHasherFactory;
    private SessionInterface $session;

    public function __construct(
        JWTTokenManagerInterface       $JWTManager,
        AppUserProvider $userProvider,
        PasswordHasherFactoryInterface $passwordHasherFactory,
        SessionInterface               $session
    )
    {
        $this->JWTManager = $JWTManager;
        $this->userProvider = $userProvider;
        $this->passwordHasherFactory = $passwordHasherFactory;
        $this->session = $session;
    }

    public function supports(Request $request): ?bool
    {
        return !$request->headers->has('Authorization')
            && !str_starts_with($request->getRequestUri(), '/api/authenticator/google/')
            && !str_starts_with($request->getRequestUri(), '/api/authenticator/confirm');
    }

    public function authenticate(Request $request): Passport
    {
        $data = json_decode($request->getContent());

        $email = $data->email;
        $password = $data->password;

        if (!$user = $this->loadUserByIdentifier($email)) {
            throw new CustomUserMessageAuthenticationException('Invalid username');
        }

        $this->setUser($user);

        $userLoader = function () use ($user) {
            return $user;
        };

        // Use the PasswordHasherFactory to create a password hasher for the user's password
        $passwordHasher = $this->passwordHasherFactory->getPasswordHasher($user);

        // Validate the password using the password hasher
        if (!$passwordHasher->verify($user->getPassword(), $password) && $user->getPassword() !== $password) {
            throw new CustomUserMessageAuthenticationException('Invalid password');
        }

        // Create a passport object with the authenticated user and credentials
        $passport = new Passport(new UserBadge($email, $userLoader), new PasswordCredentials($password));

        // Return the passport object
        return $passport;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    /**
     * @param string $identifier
     * @return UserInterface|null
     */
    public function loadUserByIdentifier(string $identifier): ?UserInterface
    {
        return $this->userProvider->loadUserByIdentifier($identifier);
    }

    /**
     * @param UserInterface $user
     * @return void
     */
    private function setUser(UserInterface $user): void
    {
        $this->session->set('_user', $user);
    }
}
