<?php

namespace Iqbalatma\LaravelJwtAuth\Exceptions;

use Exception;
use Illuminate\Http\JsonResponse;

class NullCredentialException extends Exception
{
    public function __construct(string $message = "Credentials cannot be null", int $code = JsonResponse::HTTP_INTERNAL_SERVER_ERROR)
    {
        $this->message = $message;
        $this->code = $code;
    }
}
