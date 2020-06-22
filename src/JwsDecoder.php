<?php


namespace Phore\JWT;

use Phore\JWT\Exceptions\InvalidAlgorithmException;
use Phore\JWT\Exceptions\InvalidHeaderException;
use Phore\JWT\Exceptions\InvalidJwtFormatException;
use stdClass;

/**
 * Class JwsDecoder
 * @package Phore\JWT
 *
 * Validates and decodes a JWS Token
 */
class JwsDecoder
{
    private $additionalHeaders;

    private $header;
    private $payload;
    private $signature;

    private $nested = false;

    public function __construct($additionalHeaders = [])
    {
        $this->additionalHeaders = $additionalHeaders;
    }

    public function decode(string $jwsToken)
    {
        if(!preg_match("/^([\w-]+)\.([\w-]+)\.([\w-]*)$/", $jwsToken, $jwsComponents))
            throw new InvalidJwtFormatException("JWS needs exactly three base64url-encoded components delimited by two period characters.");
        $this->header = $this->base64urlDecode($jwsComponents[1]);
        $this->payload = $this->base64urlDecode($jwsComponents[2]);
        $header = json_decode($this->header);
        $payload = json_decode($this->payload);
        if(!($header instanceof stdClass) || (!$payload instanceof stdClass))
            throw new InvalidJwtFormatException("JWS contains invalid Json.");
        $this->validateHeader($header);




        print_r($header);

//        list($this->header, $this->payload, $this->signature) = $jwsComponents;
    }

    private function base64urlDecode(string $string)
    {
        $decodedString = base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $string), true);
        if($decodedString === false)
            throw new InvalidJwtFormatException("JWS contains invalid base64 characters.");
        return $decodedString;
    }

    private function validateAlg($alg)
    {
        return JsonWebAlgorithms::isValid($alg);
    }

    private function validateHeader(stdClass $header)
    {
        if(!isset($header->alg) || !$this->validateAlg($header->alg))
            throw new InvalidAlgorithmException("Invalid algorithm '" . ($header->alg ?? 'undefined') . "'.");
        if(isset($header->cty) && strtolower($header->cty) == 'JWT') {
            $this->nested = true;
        }
        if(isset($header->crit)) {
            foreach($header->crit as $criticalHeader) {
                if(!isset($header->$criticalHeader) || !in_array($criticalHeader, $this->additionalHeaders))
                    throw new InvalidHeaderException("Critical Header parameter '$criticalHeader' is missing or not supported.");
            }
        }
    }

    private function validatePayload()
    {

    }

}
