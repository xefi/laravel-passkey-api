<?php

namespace Xefi\LaravelPasskey\Exceptions;

use Illuminate\Database\Eloquent\ModelNotFoundException;

class PasskeyNotFoundException extends ModelNotFoundException
{
    public function __construct(string $message = 'Passkey not found')
    {
        parent::__construct($message);
    }
}
