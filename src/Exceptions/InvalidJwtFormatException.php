<?php

namespace Phore\JWT\Exceptions;

/**
 * Class InvalidJwtFormatException
 *
 * Thrown when the JWT does not match the Compact Serialization format.
 * For JWS this means there has to be 3 base64url-encoded Parts, split by 2 dots.
 */
class InvalidJwtFormatException extends JwtValidationException
{
    public function __construct(
        $message = "Invalid Compact Serialization format.",
        $code = 0
    ) {
        parent::__construct($message, $code, null);
    }
}
