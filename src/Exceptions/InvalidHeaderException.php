<?php


namespace Phore\JWT\Exceptions;

/**
 * Class InvalidHeaderException
 * @package Phore\JWT\Exceptions
 *
 * Thrown if a critical header parameter is missing or cannot be understood
 */
class InvalidHeaderException extends JwtValidationException
{
    public function __construct(
        $message = "Invalid Header",
        $code = 0
    ) {
        parent::__construct($message, $code, null);
    }
}
