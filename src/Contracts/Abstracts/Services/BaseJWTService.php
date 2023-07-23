<?php

namespace Iqbalatma\LaravelJwtAuth\Contracts\Abstracts\Services;

use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuth\Exceptions\UnauthenticatedJWTException;

abstract class BaseJWTService
{
    public string $accessToken;
    public string $refreshToken;

    /**
     * @param string $accessToken
     * @return void
     */
    public function setAccessToken(string $accessToken):void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken():string
    {
        return $this->accessToken;
    }

    /**
     * @param string $refreshToken
     * @return void
     */
    public function setRefreshToken(string $refreshToken):void
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken():string
    {
        return $this->refreshToken;
    }


    /**
     * Use to make sure that request token is came from refresh token
     * @return void
     * @throws \Throwable
     */
    public static function requestShouldFromRefreshToken(): void
    {
        $tokenType = Auth::payload()->get("token_type");
        throw_if($tokenType !== "refresh", new UnauthenticatedJWTException("Cannot using access token to doing refresh token"));
    }
}
