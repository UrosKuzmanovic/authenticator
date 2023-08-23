<?php

namespace App\Service;

use App\Entity\Dto\LoginDto;
use App\Entity\User;
use App\Security\Authenticator;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
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
    private JWTTokenManagerInterface $JWTManager;
    private TokenStorageInterface $tokenStorage;
    private EventDispatcherInterface $eventDispatcher;
    private SessionInterface $session;

    public function __construct(
        Authenticator            $authenticator,
        JWTTokenManagerInterface $JWTManager,
        TokenStorageInterface    $tokenStorage,
        EventDispatcherInterface $eventDispatcher,
        SessionInterface         $session
    )
    {
        $this->authenticator = $authenticator;
        $this->JWTManager = $JWTManager;
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
     * @return LoginDto
     */
    public function login(Request $request): LoginDto
    {
        $passport = $this->authenticator->authenticate($request);

        // Create the authenticated token
        $token = $this->authenticator->createToken($passport, 'main');

        // Authenticate the user by setting the token
        $this->tokenStorage->setToken($token);

        // Fire the login event
        $event = new InteractiveLoginEvent($request, $token);
        $this->eventDispatcher->dispatch($event, SecurityEvents::INTERACTIVE_LOGIN);
        return (new LoginDto())
            ->setUser($this->getUser())
            ->setToken($this->JWTManager->create($this->getUser()));
    }

    /**
     * @param string $token
     * @return UserInterface|null
     */
    public function getUserFromToken (string $token): ?UserInterface
    {
        $token = str_replace('Bearer ', '', $token);

        $user = $this->JWTManager->parse($token);

        if (isset($user['email'])) {
            return $this->authenticator->loadUserByIdentifier($user['email']);
        } else {
            return null;
        }
    }

    /**
     * @param int $length
     * @return string
     */
    public function generateConfirmationCode(int $length = 6): string
    {
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomCode = '';

        try {
            for ($i = 0; $i < $length; $i++) {
                $randomCode .= $characters[random_int(0, $charactersLength - 1)];
            }

            return $randomCode;
        } catch (\Exception $e) {
            return 'ABCDEF';
        }
    }

}