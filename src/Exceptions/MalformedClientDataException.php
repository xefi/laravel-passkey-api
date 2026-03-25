<?php

namespace Xefi\LaravelPasskey\Exceptions;

use InvalidArgumentException;

/**
 * Exception thrown when the WebAuthn client data JSON is malformed or has an unexpected type.
 */
class MalformedClientDataException extends InvalidArgumentException
{
    public function __construct(string $message = 'Malformed client data', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
