<?php

namespace Iqbalatma\LaravelJwtAuth\Exceptions;

use Exception;
use Illuminate\Http\JsonResponse;

class InvalidCredentialException extends Exception
{
    public function __construct(string $message = "Invalid crdentials", int $code = JsonResponse::HTTP_UNAUTHORIZED)
    {
        $this->message = $message;
        $this->code = $code;
    }
}
