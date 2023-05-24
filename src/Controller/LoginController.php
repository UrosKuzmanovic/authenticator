<?php

namespace App\Controller;

use App\Entity\User;
use App\Manager\UserManager;
use App\Security\Authenticator;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Serializer\Normalizer\AbstractNormalizer;
use function Symfony\Component\String\u;

/**
 * @Route("/api/authenticator")
 */
class LoginController extends AbstractController
{

    private Authenticator $authenticator;
    private EventDispatcherInterface $eventDispatcher;
    private TokenStorageInterface $tokenStorage;
    private SessionInterface $session;
    private PasswordHasherFactoryInterface $passwordHasherFactory;

    /**
     * @param Authenticator $authenticator
     * @param TokenStorageInterface $tokenStorage
     * @param EventDispatcherInterface $eventDispatcher
     * @param SessionInterface $session
     */
    public function __construct(
        Authenticator                  $authenticator,
        TokenStorageInterface          $tokenStorage,
        PasswordHasherFactoryInterface $passwordHasherFactory,
        EventDispatcherInterface       $eventDispatcher,
        SessionInterface               $session
    )
    {
        $this->authenticator = $authenticator;
        $this->eventDispatcher = $eventDispatcher;
        $this->tokenStorage = $tokenStorage;
        $this->session = $session;
        $this->passwordHasherFactory = $passwordHasherFactory;
    }

    /**
     * @Route("/login", name="authenticator_login")
     */
    public
    function login(Request $request): JsonResponse
    {
        if ($this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => 400,
                    'message' => 'Already logged in!'
                ),
                Response::HTTP_BAD_REQUEST
            );
        }

        // Call the authenticate() method of your custom authenticator
        $passport = $this->authenticator->authenticate($request);

        // Create the authenticated token
        $token = $this->authenticator->createToken($passport, 'main');

        // Authenticate the user by setting the token
        $this->tokenStorage->setToken($token);

        // Fire the login event
        $event = new InteractiveLoginEvent($request, $token);
        $this->eventDispatcher->dispatch($event, SecurityEvents::INTERACTIVE_LOGIN);

        $this->session->set('_user', $this->getUser());

        return $this->json(
            array(
                'status' => 200,
                'message' => 'Logged in!',
                'user' => $this->getUser(),
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }

    /**
     * @Route("/logout", name="authenticator_logout")
     */
    public
    function logout(Request $request)
    {
        if (!$this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => 400,
                    'message' => 'Already logged out!'
                ),
                Response::HTTP_BAD_REQUEST
            );
        }

        $this->session->invalidate();

        $this->tokenStorage->setToken();

        return $this->json(
            array(
                'status' => 200,
                'message' => 'Logged out!',
            )
        );
    }

    /**
     * @Route("/register", name="authenticator_register")
     */
    public function register(Request $request, UserManager $userManager)
    {
        if ($this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => 400,
                    'message' => 'Already logged in!'
                ),
                Response::HTTP_BAD_REQUEST
            );
        }

        $user = new User();

        $hasher = $this->passwordHasherFactory->getPasswordHasher($user);

        $data = json_decode($request->getContent());

        if ($userManager->loadUserByIdentifier($data->email)) {
            return $this->json(
                array(
                    'status' => 409,
                    'message' => 'User with email exists!'
                ),
                Response::HTTP_CONFLICT
            );
        }

        $user->setEmail($data->email)
            ->setPassword($hasher->hash($data->password));

        $userDB = $userManager->add($user);

        if ($userDB->getId()) {// Call the authenticate() method of your custom authenticator
            $passport = $this->authenticator->authenticate($request);

            // Create the authenticated token
            $token = $this->authenticator->createToken($passport, 'main');

            // Authenticate the user by setting the token
            $this->tokenStorage->setToken($token);

            // Fire the login event
            $event = new InteractiveLoginEvent($request, $token);
            $this->eventDispatcher->dispatch($event, SecurityEvents::INTERACTIVE_LOGIN);

            $this->session->set('_user', $this->getUser());

            return $this->json(
                array(
                    'status' => 200,
                    'message' => 'Logged in!',
                    'user' => $this->getUser(),
                ),
                Response::HTTP_OK,
                [],
                [AbstractNormalizer::GROUPS => ['view']]
            );
        } else {
            return $this->json(
                array(
                    'status' => 500,
                    'message' => 'There was an error while saving user!'
                ),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * @Route("/user", name="authenticator_user")
     */
    public
    function userAction(Request $request)
    {
        if (!$this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => 401,
                    'message' => 'Unauthorized!'
                ),
                Response::HTTP_UNAUTHORIZED
            );
        }

        /** @var User $user */
        $user = $this->session->get('_user');

        return $this->json(
            array(
                'status' => 200,
                'message' => 'Logged User',
                'user' => $user,
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }
}
