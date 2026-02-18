<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when a COSE key cannot be parsed or has an invalid format.
 */
class InvalidCoseKeyException extends RuntimeException
{
    public function __construct(string $message = 'Invalid COSE key format', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
