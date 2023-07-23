<?php

namespace Iqbalatma\LaravelJwtAuth\Middleware;

use Closure;
use Iqbalatma\LaravelJwtAuth\Services\JWTBlacklistService;
use Illuminate\Auth\Middleware\Authenticate as Middleware;


class AuthenticateJWT extends Middleware
{
    /**
     * @param $request
     * @param Closure $next
     * @param ...$guards
     * @return mixed
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Throwable
     */
    public function handle($request, Closure $next, ...$guards)
    {
        $this->authenticate($request, $guards);

        if ((new JWTBlacklistService())->isTokenBlacklisted())
            $this->unauthenticated($request, $guards);

        return $next($request);
    }
}
