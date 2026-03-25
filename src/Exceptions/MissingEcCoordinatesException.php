<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when EC public key coordinates (x, y) are missing from a COSE key.
 */
class MissingEcCoordinatesException extends RuntimeException
{
    public function __construct(string $message = 'Missing EC coordinates in COSE key', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
