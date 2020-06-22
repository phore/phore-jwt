<?php

namespace Phore\JWT\Exceptions;

/**
 * Class InvalidSignatureException
 *
 * Thrown when the signature cannot be validated with the provided algorithm and key
 */
class InvalidSignatureException extends JwtValidationException
{
    public function __construct(
        $message = "Invalid Signature.",
        $code = 0
    ) {
        parent::__construct($message, $code, null);
    }
}
