<?php

namespace Iqbalatma\LaravelJwtAuth\Services;


use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuth\Contracts\Abstracts\Services\BaseJWTService;
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
    public function invokeAccessToken(?array $credentials = null, ?Authenticatable $user = null): string|null
    {
        /**
         * Use to set token claims
         */
        $accessTTL = config("jwt.ttl", 60);
        $authClaim = Auth::claims(["token_type" => "access"])
            ->setTTL($accessTTL);

        /**
         * if request come from authenticated user, set $user into that authenticated user
         */
        if (Auth::user()) $user = Auth::user();


        /**
         * if user not null, get new token via authenticated user
         * if user null,  get token via credential attempt
         */
        if ($user) {
            $token = $authClaim->login($user);
        } else {
            throw_if(!$credentials, new NullCredentialException());
            $token = $authClaim->attempt($credentials);
        }

        $this->setAccessToken($token);

        return $token;
    }


    /**
     * @return string
     * @throws \Throwable
     */
    public function invokeRefreshToken(): string
    {
        throw_if(!Auth::user(), new UnauthenticatedJWTException());

        $token = Auth::claims(["token_type" => "refresh"])
            ->setTTL(config("jwt.refresh_ttl"))
            ->login(Auth::user());


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
        throw_if(!Auth::user(), new UnauthenticatedJWTException());

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
        $this->invokeAccessToken(user: Auth::user());
        $this->invokeRefreshToken();
    }
}
