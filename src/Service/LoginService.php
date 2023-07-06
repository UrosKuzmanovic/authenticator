<?php

namespace App\Service;

use App\Entity\User;
use App\Security\Authenticator;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

class LoginService
{
    private Authenticator $authenticator;
    private TokenStorageInterface $tokenStorage;
    private EventDispatcherInterface $eventDispatcher;
    private SessionInterface $session;

    public function __construct(
        Authenticator            $authenticator,
        TokenStorageInterface    $tokenStorage,
        EventDispatcherInterface $eventDispatcher,
        SessionInterface         $session
    )
    {
        $this->authenticator = $authenticator;
        $this->tokenStorage = $tokenStorage;
        $this->eventDispatcher = $eventDispatcher;
        $this->session = $session;
    }

    /**
     * @param UserInterface $user
     * @return void
     */
    public function setUser(UserInterface $user): void
    {
        $this->session->set('_user', $user);
    }

    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        return $this->session->get('_user');
    }

    /**
     * @param string $email
     * @param string|null $password
     * @return Request
     */
    public function createAuthenticatorRequest(string $email, string $password = null): Request
    {
        return Request::create('/url', 'POST', [], [], [], [],
            json_encode([
                'email' => $email,
                'password' => $password
            ])
        );
    }

    /**
     * @param Request $request
     * @return void
     */
    public function login(Request $request): void
    {
        $passport = $this->authenticator->authenticate($request);

        // Create the authenticated token
        $token = $this->authenticator->createToken($passport, 'main');

        // Authenticate the user by setting the token
        $this->tokenStorage->setToken($token);

        // Fire the login event
        $event = new InteractiveLoginEvent($request, $token);
        $this->eventDispatcher->dispatch($event, SecurityEvents::INTERACTIVE_LOGIN);
    }

}