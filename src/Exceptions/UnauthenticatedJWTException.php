<?php

namespace Iqbalatma\LaravelJwtAuth\Exceptions;

use Exception;
use Illuminate\Http\JsonResponse;

class UnauthenticatedJWTException extends Exception
{
    public function __construct(string $message = "Invalid or expired token", int $code = JsonResponse::HTTP_UNAUTHORIZED)
    {
        $this->message = $message;
        $this->code = $code;
    }
}
