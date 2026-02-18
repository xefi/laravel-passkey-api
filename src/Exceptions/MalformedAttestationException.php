<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when the attestation object is missing required fields (e.g. authData).
 */
class MalformedAttestationException extends RuntimeException
{
    public function __construct(string $message = 'Malformed attestationObject: missing authData', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
