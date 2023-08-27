<?php

namespace App\Controller;

use App\Entity\User;
use App\Manager\UserManager;
use App\Security\Authenticator;
use App\Service\LoginService;
use App\Util\HttpRequestMessages;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
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
    public function login(Request $request): JsonResponse
    {
        $loginDto = $this->loginService->login($request);

        return $this->json(
            array(
                'status' => Response::HTTP_OK,
                'message' => HttpRequestMessages::LOGGED_IN,
                'user' => $loginDto->getUser(),
                'token' => $loginDto->getToken()
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }

    /**
     * @Route("/logout", name="authenticator_logout")
     */
    public function logout(Request $request): JsonResponse
    {
        if (!$this->isGranted('ROLE_USER')) {
            return $this->json(
                array(
                    'status' => Response::HTTP_UNAUTHORIZED,
                    'message' => HttpRequestMessages::UNAUTHORIZED
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
    public function register(Request $request, UserManager $userManager): JsonResponse
    {
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
            ->setPassword($hasher->hash($data->password))
            ->setFirstName($data->firstName)
            ->setLastName($data->lastName)
            ->setUsername($data->username)
            ->setPictureUrl($data->pictureUrl)
            ->setEnabled(!!$data->enabled);

        $userDB = $userManager->save($user);

        if ($userDB->getId()) {
            if ($data->enabled) {
                $loginDto = $this->loginService->login(
                    $this->loginService->createAuthenticatorRequest(
                        $userDB->getEmail(),
                        $userDB->getEmail()
                    )
                );

                return $this->json(
                    array(
                        'status' => Response::HTTP_OK,
                        'message' => HttpRequestMessages::LOGGED_IN,
                        'user' => $loginDto->getUser(),
                        'token' => $loginDto->getToken()
                    ),
                    Response::HTTP_OK,
                    [],
                    [AbstractNormalizer::GROUPS => ['view']]
                );
            } else {
                $userDB = $userManager->save(
                    $userDB->setConfirmationCode(
                        $this->loginService->generateConfirmationCode()
                    )
                );

                return $this->json(
                    array(
                        'status' => Response::HTTP_OK,
                        'message' => HttpRequestMessages::REGISTERED,
                        'user' => $userDB,
                    ),
                    Response::HTTP_OK,
                    [],
                    [AbstractNormalizer::GROUPS => ['view']]
                );
            }
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
     * @Route("/confirm", name="authenticator_confirm")
     */
    public function confirm(Request $request, UserManager $userManager): JsonResponse
    {
        $data = json_decode($request->getContent());

        if ($data->email && $data->confirmationCode) {
            $userDB = $userManager->confirmUser($data->email, $data->confirmationCode);

            $loginDto = $this->loginService->login(
                $this->loginService->createAuthenticatorRequest(
                    $userDB->getEmail(),
                    $userDB->getPassword()
                )
            );

            if ($userDB) {
                return $this->json(
                    array(
                        'status' => Response::HTTP_OK,
                        'message' => HttpRequestMessages::ENABLED,
                        'user' => $loginDto->getUser(),
                        'token' => $loginDto->getToken(),
                    )
                );
            }

            return $this->json(
                array(
                    'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
                    'message' => HttpRequestMessages::SAVING_ERROR,
                )
            );
        }

        return $this->json(
            array(
                'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
                'message' => HttpRequestMessages::SAVING_ERROR,
            )
        );
    }

    /**
     * @Route("/user", name="authenticator_user")
     */
    public function userAction(Request $request): JsonResponse
    {
        $token = $request->headers->get('Authorization');

        if (!$token) {
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
                'user' => $this->loginService->getUserFromToken($token),
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }
}
