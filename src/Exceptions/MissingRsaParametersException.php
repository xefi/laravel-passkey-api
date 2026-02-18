<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when RSA key parameters (modulus/exponent) are missing from a COSE key.
 */
class MissingRsaParametersException extends RuntimeException
{
    public function __construct(string $message = 'Missing RSA parameters in COSE key', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
