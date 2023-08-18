<?php

namespace Iqbalatma\LaravelJwtAuth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Iqbalatma\LaravelJwtAuth\Services\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuth\Services\JWTService;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Auth\Middleware\Authenticate as Middleware;

class RefreshTokenMiddleware extends Middleware
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
        $refreshToken = $request->cookie("refresh_token");
        $request->headers->set('authorization', "Bearer $refreshToken");

        $this->authenticate($request, $guards);

        (new JWTService())->checkIncidentTime();

//        // when incident date time is null probably incident just happening, set again
//        if (!$incidentTime = Cache::get("jwt.incident_date_time")) {
//            $incidentTime = Cache::forever("jwt.incident_date_time", time());
//        }

//        if ((new JWTBlacklistService())->isTokenBlacklisted($incidentTime))
//            $this->unauthenticated($request, $guards);

        JWTService::requestShouldFromRefreshToken();

        return $next($request);
    }


    /**
     * Get the path the user should be redirected to when they are not authenticated.
     */
    protected function redirectTo(Request $request): ?string
    {
        return $request->expectsJson() ? null : route('login');
    }
}
