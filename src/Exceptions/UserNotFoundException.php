<?php

namespace Xefi\LaravelPasskey\Exceptions;

use Illuminate\Database\Eloquent\ModelNotFoundException;

class UserNotFoundException extends ModelNotFoundException
{
    public function __construct(string $message = 'User not found')
    {
        parent::__construct($message);
    }
}
