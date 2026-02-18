<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when a COSE algorithm identifier is not supported.
 */
class UnsupportedAlgorithmException extends RuntimeException
{
    public function __construct(string $message = 'Unsupported algorithm', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
