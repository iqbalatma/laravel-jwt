<?php

namespace Iqbalatma\LaravelJwtAuth\Services;


use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuth\Contracts\Abstracts\Services\BaseJWTService;
use Iqbalatma\LaravelJwtAuth\Exceptions\InvalidCredentialException;
use Iqbalatma\LaravelJwtAuth\Exceptions\NullCredentialException;
use Iqbalatma\LaravelJwtAuth\Exceptions\UnauthenticatedJWTException;

class JWTService extends BaseJWTService
{
    /**
     * @param array|null $credentials
     * @param Authenticatable|null $user
     * @return string|null
     * @throws \Throwable
     */
    public function invokeAccessToken(?array $credentials = null, ?Authenticatable $user = null): string|bool|null
    {
        /**
         * Use to set token claims
         */
        $authClaim = Auth::claims(["token_type" => "access"])
            ->setTTL(config("jwt.ttl", 60));

        /**
         * if user not null, get new token via authenticated user (mostly use by action refreshing token)
         * if user null,  get token via credential attempt, if credentials is empty or null throw an exception
         */
        if ($user = Auth::user()) {
            $token = $authClaim->login($user);
        } else {
            throw_if(!$credentials, new NullCredentialException());
            $token = $authClaim->attempt($credentials);
        }

        /**
         * This is when credentials is invalid (which mean token will be false)
         */
        throw_if(!$token, new InvalidCredentialException());

        $this->setAccessToken($token);

        return $token;
    }


    /**
     * invoke refresh token must be accessed from authenticated user
     *
     *
     * @return string
     * @throws \Throwable
     */
    public function invokeRefreshToken(): string
    {
        throw_if(!$user = Auth::user(), new UnauthenticatedJWTException());

        $token = Auth::claims(["token_type" => "refresh"])
            ->setTTL(config("jwt.refresh_ttl"))
            ->login($user);

        $this->setRefreshToken($token);

        return $token;
    }


    /**
     * Use to refresh token using refresh token and will invoke new access and refresh token
     * @return void
     * @throws \Throwable
     */
    public function refreshToken(): void
    {
        throw_if(!$user = Auth::user(), new UnauthenticatedJWTException());

        /**
         * make sure request token come from refresh token type
         */
        self::requestShouldFromRefreshToken();

        /**
         * invalidate previous invoked access and refresh token
         */
        (new JWTBlacklistService())->invalidateCurrentToken(true);

        /**
         * invoke new access and refresh token
         */
        $this->invokeAccessToken(user: $user);
        $this->invokeRefreshToken();
    }
}
