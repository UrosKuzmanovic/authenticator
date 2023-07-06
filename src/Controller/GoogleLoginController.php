<?php

namespace App\Controller;

use App\Service\GoogleLoginService;
use App\Util\HttpRequestMessages;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\Normalizer\AbstractNormalizer;

/**
 * @Route("/api/authenticator/google")
 */
class GoogleLoginController extends AbstractController
{

    private GoogleLoginService $googleLoginService;

    public function __construct(
        GoogleLoginService $googleLoginService
    )
    {
        $this->googleLoginService = $googleLoginService;
    }

    /**
     * @Route("/permission", name="authenticator_google_permission")
     */
    public function googlePermission()
    {
        $this->googleLoginService->getPermission();
    }

    /**
     * @Route("/login", name="authenticator_google_login")
     */
    public function googleLogin(Request $request)
    {
        $user = $this->googleLoginService->login($request);

        return $this->json(
            array(
                'status' => Response::HTTP_OK,
                'message' => HttpRequestMessages::LOGGED_IN,
                'user' => $user,
            ),
            Response::HTTP_OK,
            [],
            [AbstractNormalizer::GROUPS => ['view']]
        );
    }
}
