<?php

namespace Phore\JWT\Exceptions;

/**
 * Class InvalidAlgorithmException
 *
 * Thrown when the JWT contains no 'alg' parameter or the provided 'alg' value is non-standard, not supported or
 * does not match any of the provided keys
 */
class InvalidAlgorithmException extends JwtValidationException
{
    public function __construct(
        $message = "Invalid Algorithm",
        $code = 0
    ) {
        parent::__construct($message, $code, null);
    }
}
