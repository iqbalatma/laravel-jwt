<?php

namespace Iqbalatma\LaravelJwtAuth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuth\Services\JWTBlacklistService;
use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Iqbalatma\LaravelJwtAuth\Services\JWTService;


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

        // when incident date time is null probably incident just happening, set again
        if (!$incidentTime = Cache::get("jwt.incident_date_time")) {
            $incidentTime = Cache::forever("jwt.incident_date_time", time());
        }

        if ((new JWTBlacklistService())->isTokenBlacklisted($incidentTime))
            $this->unauthenticated($request, $guards);

        JWTService::requestShouldFromAccessToken();

        return $next($request);
    }
}
