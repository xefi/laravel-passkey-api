<?php

namespace Xefi\LaravelPasskey\Exceptions;

use RuntimeException;

/**
 * Exception thrown when a WebAuthn signature verification fails.
 */
class InvalidSignatureException extends RuntimeException
{
    public function __construct(string $message = 'Invalid signature', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
