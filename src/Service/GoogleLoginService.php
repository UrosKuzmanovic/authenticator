<?php

namespace App\Service;

use App\Entity\Dto\LoginDto;
use App\Entity\User;
use App\Manager\UserManager;
use App\Util\GoogleLoginParameters;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class GoogleLoginService
{

    private LoginService $loginService;
    private UserManager $userManager;
    private PasswordHasherFactoryInterface $passwordHasherFactory;

    public function __construct(
        LoginService $loginService,
        UserManager  $userManager,
        PasswordHasherFactoryInterface $passwordHasherFactory
    )
    {
        $this->loginService = $loginService;
        $this->userManager = $userManager;
        $this->passwordHasherFactory = $passwordHasherFactory;
    }

    /**
     * @return void
     */
    public function getPermission(): void
    {
        $params = array(
            'client_id' => GoogleLoginParameters::CLIENT_ID,
            'redirect_uri' => GoogleLoginParameters::REDIRECT_URI,
            'scope' => GoogleLoginParameters::SCOPE,
            'response_type' => GoogleLoginParameters::RESPONSE_TYPE
        );

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, GoogleLoginParameters::AUTH_URL);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);

        if ($response === false) {
            echo 'cURL error: ' . curl_error($ch);
        } else {
            echo $response;
        }

        curl_close($ch);
    }

    public function login(Request $request)
    {
        try {
            $accessToken = $this->getAccessToken($request);

            $curl = curl_init();

            $headers = array(
                'Authorization: Bearer ' . $accessToken
            );

            curl_setopt($curl, CURLOPT_URL, GoogleLoginParameters::USER_INFO_URL);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

            $response = curl_exec($curl);
            $error = curl_error($curl);

            curl_close($curl);

            if ($error) {
                echo "cURL Error: " . $error;

                // TODO ADD RETURN
                return null;
            } else {
                return $this->saveGoogleUser($response);
            }
        } catch (RequestException|GuzzleException $e) {
            if ($e->hasResponse()) {
                $response = $e->getResponse();
                $body = $response->getBody();
                echo $body;
            } else {
                echo 'Request failed: ' . $e->getMessage();
            }

            // TODO ADD RETURN
            return null;
        }
    }

    /**
     * @param Request $request
     * @return string
     * @throws GuzzleException
     */
    private function getAccessToken(Request $request): string
    {
        $response = (new Client())->post(
            GoogleLoginParameters::TOKEN_URL,
            [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'form_params' => [
                    'client_id' => GoogleLoginParameters::CLIENT_ID,
                    'client_secret' => GoogleLoginParameters::CLIENT_SECRET,
                    'redirect_uri' => GoogleLoginParameters::REDIRECT_URI,
                    'code' => $request->get('code'),
                    'grant_type' => GoogleLoginParameters::GRANT_TYPE,
                ]
            ]
        );

        return json_decode($response->getBody()->getContents())->access_token;
    }

    private function getUserData($userData)
    {

        if (!$userDB = $this->userManager->loadUserByIdentifier($userData->email)) {
            $userDB = new User();
            $userDB->setEmail($userData->email);
        }

        $hasher = $this->passwordHasherFactory->getPasswordHasher($userDB);

        $userDB->setPassword($hasher->hash($userData->email));
        $userDB->setFirstName($userData->given_name);
        $userDB->setLastName($userData->family_name);
        $userDB->setUsername($userData->email);
        $userDB->setName($userData->name);
        $userDB->setPictureUrl($userData->picture);
        $userDB->setGoogleId($userData->id);
        $userDB->setLoggedAt(new \DateTime());

        return $userDB;
    }

    /**
     * @param string $response
     * @return LoginDto
     */
    private function saveGoogleUser(string $response): LoginDto
    {
        $loginDto = new LoginDto();

        $user = $this->getUserData(json_decode($response));
        $userDB = $this->userManager->save($user);

        if ($userDB->getId()) {
            $loginDto = $this->loginService->login(
                $this->loginService->createAuthenticatorRequest(
                    $userDB->getEmail(),
                    $userDB->getEmail()
                )
            );
            $this->loginService->setUser($userDB);

            $loginDto->setUser($userDB);
        }

        return $loginDto;
    }
}