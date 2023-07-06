<?php

namespace App\Util;

class GoogleLoginParameters
{
    public const AUTH_URL = 'https://accounts.google.com/o/oauth2/auth';
    public const CLIENT_ID = '326023008453-tbv68jr16tet7opn7o5837p58ilro2nf.apps.googleusercontent.com';
    public const CLIENT_SECRET = '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';
    public const GRANT_TYPE = 'authorization_code';
    public const REDIRECT_URI = 'http://localhost/api/authenticator/google/login';
    public const RESPONSE_TYPE = 'code';
    public const SCOPE = 'profile email';
    public const TOKEN_URL = 'https://oauth2.googleapis.com/token';
    public const USER_INFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
}