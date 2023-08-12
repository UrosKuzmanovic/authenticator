<?php

namespace App\Controller;

use App\Manager\UserManager;
use App\Service\GoogleLoginService;
use App\Service\LoginService;
use App\Util\HttpRequestMessages;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\Normalizer\AbstractNormalizer;

/**
 * @Route("/api/authenticator/google")
 */
class GoogleLoginController extends AbstractController
{

    private UserManager $userManager;
    private LoginService $loginService;
    private GoogleLoginService $googleLoginService;

    public function __construct(
        UserManager  $userManager,
        LoginService $loginService,
        GoogleLoginService $googleLoginService
    )
    {
        $this->userManager = $userManager;
        $this->loginService = $loginService;
        $this->googleLoginService = $googleLoginService;
    }

    /**
     * @Route("/permission", name="authenticator_google_permission")
     */
    public function googlePermission(Request $request)
    {
        $this->googleLoginService->getPermission();
    }

    /**
     * @Route("/login", name="authenticator_google_login")
     */
    public function googleLogin(Request $request)
    {
        $loginDto = $this->googleLoginService->login($request);

        if ($loginDto && $loginDto->getUser()) {
            $userId = $loginDto->getUser()->getId();
            $token = $loginDto->getToken();

            // TODO get localhost from .env
            echo '
                    <!DOCTYPE html>
                    <html>
                      <body>
                        <p>Authentication Successful!</p>
                        <p>Automatically closing this tab in <span id="countdown">3</span> seconds...</p>
                      
                        <script>
                            window.opener.postMessage(
                                ' . json_encode(['userId' => $userId, 'token' => $token]) . ', 
                                \'http://localhost:4200/login\')
                            window.close();
                          </script>
                      </body>
                    </html>
            ';
            die;
        }

        return $this->json(
            array(
                'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
                'message' => 'Error'
            ),
            Response::HTTP_BAD_REQUEST
        );
    }

    /**
     * @Route("/user", name="get_google_user")
     */
    public function getGoogleUser(Request $request): JsonResponse
    {
        if ($userId = json_decode($request->getContent())->userId) {
            $userDB = $this->userManager->findOneBy(['id' => $userId]);

            $loginDto = $this->loginService->login(
                $this->loginService->createAuthenticatorRequest(
                    $userDB->getEmail(),
                    $userDB->getEmail()
                )
            );

            return $this->json([
                'status' => Response::HTTP_OK,
                'message' => 'OK',
                'user' => $loginDto->getUser(),
                'token' => $loginDto->getToken()
            ]);
        }

        return $this->json([
            'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
            'message' => 'not ok',
        ]);
    }
}
