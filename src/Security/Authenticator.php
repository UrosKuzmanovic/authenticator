<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class Authenticator extends AbstractAuthenticator

{

    private UserProviderInterface $userProvider;
    private PasswordHasherFactoryInterface $passwordHasherFactory;

    public function __construct(UserProviderInterface $userProvider, PasswordHasherFactoryInterface $passwordHasherFactory)
    {
        $this->userProvider = $userProvider;
        $this->passwordHasherFactory = $passwordHasherFactory;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        $data = json_decode($request->getContent());

        $email = $data->email;
        $password = $data->password;

        if (!$user = $this->userProvider->loadUserByIdentifier($email)) {
            throw new CustomUserMessageAuthenticationException('Invalid username or password');
        }

        $userLoader = function () use ($user) {
          return $user;
        };

        // Use the PasswordHasherFactory to create a password hasher for the user's password
        $passwordHasher = $this->passwordHasherFactory->getPasswordHasher($user);

        // Validate the password using the password hasher
        if (!$passwordHasher->verify($user->getPassword(), $password)) {
            throw new CustomUserMessageAuthenticationException('Invalid username or password');
        }

        // Create a passport object with the authenticated user and credentials
        $passport = new Passport(new UserBadge($email, $userLoader), new PasswordCredentials($password));

        // Add CSRF token badge if needed
        // TODO dodati csrf token
//        $csrfToken = $request->request->get('_csrf_token');
//        if ($csrfToken) {
//            $passport->addBadge(new CsrfTokenBadge('authenticate', $csrfToken));
//        }

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
}
