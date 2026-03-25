<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when the attestation object has an invalid or unexpected format.
 */
class InvalidAttestationFormatException extends RuntimeException
{
    public function __construct(string $message = 'Invalid attestation object format', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
