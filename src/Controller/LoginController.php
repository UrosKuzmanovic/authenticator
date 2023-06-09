<?php

namespace App\Controller;

use App\Entity\User;
use App\Manager\UserManager;
use App\Security\Authenticator;
use App\Service\LoginService;
use App\Util\HttpRequestMessages;
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
    private LoginService $loginService;
    private TokenStorageInterface $tokenStorage;
    private SessionInterface $session;
    private PasswordHasherFactoryInterface $passwordHasherFactory;

    /**
     * @param LoginService $loginService
     * @param TokenStorageInterface $tokenStorage
     * @param PasswordHasherFactoryInterface $passwordHasherFactory
     * @param SessionInterface $session
     */
    public function __construct(
        LoginService                   $loginService,
        TokenStorageInterface          $tokenStorage,
        PasswordHasherFactoryInterface $passwordHasherFactory,
        SessionInterface               $session
    )
    {
        $this->loginService = $loginService;
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
                    'status' => Response::HTTP_BAD_REQUEST,
                    'message' => HttpRequestMessages::ALREADY_LOGGED_IN
                ),
                Response::HTTP_BAD_REQUEST
            );
        }

        $this->loginService->login($request);
        $this->loginService->setUser($this->getUser());

        return $this->json(
            array(
                'status' => Response::HTTP_OK,
                'message' => HttpRequestMessages::LOGGED_IN,
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
                    'status' => Response::HTTP_BAD_REQUEST,
                    'message' => HttpRequestMessages::ALREADY_LOGGED_IN
                ),
                Response::HTTP_BAD_REQUEST
            );
        }

        $this->session->invalidate();

        $this->tokenStorage->setToken();

        return $this->json(
            array(
                'status' => Response::HTTP_OK,
                'message' => HttpRequestMessages::LOGGED_OUT,
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
                    'status' => Response::HTTP_BAD_REQUEST,
                    'message' => HttpRequestMessages::ALREADY_LOGGED_IN
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
                    'status' => Response::HTTP_CONFLICT,
                    'message' => HttpRequestMessages::EMAIL_EXISTS
                ),
                Response::HTTP_CONFLICT
            );
        }

        $user->setEmail($data->email)
            ->setPassword($hasher->hash($data->password));

        $userDB = $userManager->save($user);

        if ($userDB->getId()) {
            $this->loginService->login($request);
            $this->loginService->setUser($this->getUser());

            return $this->json(
                array(
                    'status' => Response::HTTP_OK,
                    'message' => HttpRequestMessages::LOGGED_IN,
                    'user' => $this->getUser(),
                ),
                Response::HTTP_OK,
                [],
                [AbstractNormalizer::GROUPS => ['view']]
            );
        } else {
            return $this->json(
                array(
                    'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
                    'message' => HttpRequestMessages::SAVING_ERROR
                ),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * @Route("/user", name="authenticator_user")
     */
    public function userAction(Request $request)
    {
        if (!$this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => Response::HTTP_UNAUTHORIZED,
                    'message' => HttpRequestMessages::UNAUTHORIZED
                ),
                Response::HTTP_UNAUTHORIZED
            );
        }

        return $this->json(
            array(
                'status' => Response::HTTP_OK,
                'message' => HttpRequestMessages::LOGGED_USER,
                'user' => $this->loginService->getUser(),
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }
}
