<?php

namespace Iqbalatma\LaravelJwtAuth\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuth\Exceptions\UnauthenticatedJWTException;

class JWTBlacklistService
{
    public const CACHE_PREFIX_KEY = "jwt";

    /**
     * @param bool $isInvalidateBothTokenType
     * @return void
     */
    public function invalidateCurrentToken(bool $isInvalidateBothTokenType = false): void
    {
        $payload = Auth::payload();
        $iat = $payload->get("iat");
        $userId = Auth::id();
        $cachePrefixKey = self::CACHE_PREFIX_KEY;

        /**
         * Config TTL is set with minutes format, and need to multiplies with 60 to make it in second format
         * Need to add additional time (5 minutes), just to make sure that expire token is below expire cache saved
         */
        $accessTTL = (config("jwt.ttl") * 60) + (60*60*5);
        $refreshTTL = (config("jwt.refresh_ttl") * 60) + (60*60*5);
        if (!$isInvalidateBothTokenType) {
            $tokenType = $payload->get("token_type");
            $ttl = $tokenType === "refresh" ? $refreshTTL : $accessTTL;
            //example : jwt.refresh.uuid
            Cache::put("$cachePrefixKey.$tokenType.$userId", $iat, $ttl);
        } else {
            Cache::put("$cachePrefixKey.access.$userId", $iat, $accessTTL);
            Cache::put("$cachePrefixKey.refresh.$userId", $iat, $refreshTTL);
        }
    }


    /**
     * Use to check is current token is blacklisted or not against data cache
     * @return bool
     * @throws \Throwable
     */
    public function isTokenBlacklisted(): bool
    {
        /**
         * use to check is user is authenticated
         */
        throw_if(!Auth::check(), new UnauthenticatedJWTException());

        /**
         * define variable
         */
        $payload = Auth::payload();
        $iat = $payload->get("iat");
        $tokenType = $payload->get("token_type");
        $cachePrefix = self::CACHE_PREFIX_KEY;
        $userId = Auth::id();

        /**
         * get data from cache
         */
        $dataCache = Cache::get("$cachePrefix.$tokenType.$userId");

        /**
         * use to check is token on blacklist
         * if datacache exists
         * and
         * blacklisted iat is greater or equal to requested token iat
         * it's mean tokens are on blacklisted
         */
        return $dataCache && $dataCache >= $iat;
    }
}
