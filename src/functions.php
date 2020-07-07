<?php

use Phore\JWT\Exceptions\InvalidJwtFormatException;

function jsonEncode($data) : string
{
    $json = json_encode($data, JSON_PRESERVE_ZERO_FRACTION|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    if($json === false)
        throw new InvalidArgumentException("Failed to json encode data");
    return $json;
}

function base64urlEncode(string $string) : string
{
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
}

function base64urlDecode(string $string)
{
    $decodedString = base64_decode(str_replace(['-', '_'], ['+', '/'], $string), true);
    if($decodedString === false)
        throw new InvalidJwtFormatException("Token contains invalid base64 characters.");
    return $decodedString;
}
